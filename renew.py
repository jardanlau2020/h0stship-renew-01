#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Host-Ship (Jexactyl/Pterodactyl 系) 自动续约 —— 已迁移到 renew-kit。

公共部分（重试 / 结果分类 / Telegram / 报告排版）交给 renewkit，
本文件只保留 Host-Ship 的业务逻辑：认证 + 续期补点。

═══ 2026-11-23 认证顺序重构：API Key 优先 ═══
面板 2026-10 起在登录接口启用 Cloudflare Turnstile（SiteConfiguration 里
recaptcha.provider=turnstile），纯 HTTP 账密登录固定回
400 "Failed to validate the captcha."，于是历史上只能靠人手贴 jexactyl_session
cookie 续命。而那个 cookie 活不过站方的 522 故障（11-23 两个账号同时 401，
其中一个才刷了 2 天，远没到 6 日 TTL）。

实测（2026-11-23，无凭证探测 + 两个上游实现交叉验证）：
  POST /api/client/servers/{id}/renew + Authorization: Bearer <key>  → 认
  同一条路由 + X-Requested-With / Referer / X-XSRF-TOKEN            → 419 CSRF mismatch
也就是说这条路由同时接受 sanctum API Key 和浏览器 session，**只要不带那三个头**。
所以现在认证顺序是：

  1) API Key（HS_API_KEY，面板 Account → API，ptlc_ 开头）——纯 HTTP，无登录、无 Turnstile、无 cookie、无 TTL
  2) cookie（JEXACTYL_SESSION）——旧路径，保留作兜底
  3) 账密（PANEL_USER / PANEL_PASS）——Turnstile 使然基本走不通，留作最后尝试

用法（环境变量）：
    HS_API_KEY                                  首选，纯 Bearer
    JEXACTYL_SESSION                            可选，cookie 兜底
    PANEL_URL / PANEL_USER / PANEL_PASS / SERVER_IDS
    TG_BOT_TOKEN / TG_CHAT_ID
    DRY_RUN=1 时只检查不续期
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.parse

from renewkit import Outcome, RenewReport, notify
from renewkit import env
from renewkit.http import TransientError, build_session, request
from renewkit.timeutil import days_left

PANEL = env.get("PANEL_URL", "https://panel.host-ship.com").rstrip("/")
USER = env.get("PANEL_USER")
PASS = env.get("PANEL_PASS")
API_KEY = env.get("HS_API_KEY", "")
SERVER_IDS = env.get_list("SERVER_IDS", default="3dee8360")
DRY_RUN = env.dry_run()

# 续期补点：面板一次 POST 直接顶到封顶（2026-11 实测封顶 14 日），
# 目标天数留在封顶之下一点，避免每次都被 400 撞回来。
TOPUP_MAX_EXTRA = env.get_int("TOPUP_MAX_EXTRA", 3)
TOPUP_INTERVAL_S = env.get_int("TOPUP_INTERVAL_S", 65)
TOPUP_GOAL_DAYS = env.get_int("TOPUP_GOAL_DAYS", 13)

SERVICE = "Host-Ship"

# 认证模式：决定续期请求带不带浏览器那套头。
AUTH_API = "api_key"
AUTH_COOKIE = "cookie"
AUTH_PASSWORD = "password"

# ══════════════════ 2026-11-23 上游不可达不再算成功 ══════════════════
# 旧行为（renewkit v0.5.3 的语义）：面板 5xx / 连不上 → TransientError →
# 记 Outcome.TRANSIENT，而 Outcome.is_error 只认 FAILED，于是 exit 0、
# job 标绿。源站报 HTTP 522 时脚本"本次跳过"被当成成功，一轮轮过去没人在意，
# cookie 每跳过一轮就老一点，最后静默烂掉。
#
# 现在三类判定分开：
#   ✅ 真续期成功 —— 拿到新到期日，且确实往后推了（读不到 / 没变化 → 结果未确认）
#   🟢 未到续期窗口 —— renewable=false，正常跳过，绿灯但要写明原因
#   ⚠️ 上游不可达 —— 522 / 源站挂 / 超时，**不算成功**：run 必须非绿
# 另外连续 UPSTREAM_STREAK_THRESHOLD 轮上游不可达时，升级成一条醒目的告警
# （只发一次），避免源站长期挂着而没人发现。
STATE_FILE = env.get("HS_UPSTREAM_STATE", "hs_upstream_state.json")
UPSTREAM_STREAK_THRESHOLD = env.get_int("UPSTREAM_STREAK_THRESHOLD", 3)


def _load_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(st: dict) -> None:
    # 状态只是计数辅助，写不进去不能影响本轮结论。
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(st, fh, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception as exc:
        log(f"  ⚠️ 上游故障计数写入失败（不影响本轮结论）: {exc}")


def _upstream_codes(report) -> str:
    """从 TRANSIENT 明细里抠出 HTTP 状态码，用于通知里点名（如 522）。"""
    codes = set()
    for r in report.results:
        if r.outcome is Outcome.TRANSIENT:
            for m in re.finditer(r"HTTP\s*(\d{3})", r.detail or ""):
                codes.add(m.group(1))
    return "/".join(sorted(codes)) if codes else "源站不可达"


def finalize(report: RenewReport) -> int:
    """统一收尾：发通知 + 三类判定 + 上游不可达时的非绿与连续告警。"""
    exit_code = report.finish(notify_tg=False)   # 只渲染 + 打印，通知统一在这里发
    worst = report.worst
    upstream_down = worst is Outcome.TRANSIENT

    st = _load_state()
    streak = int(st.get("upstream_streak") or 0)
    alerted = bool(st.get("upstream_alerted"))
    if upstream_down:
        streak += 1
    else:
        streak, alerted = 0, False

    text = report.render()
    if upstream_down:
        # 上游不可达 ≠ 成功：run 必须非绿，否则又会静默烂掉。
        exit_code = 1
        code_txt = _upstream_codes(report)
        text += (f"\n\n⚠️ 上游面板不可用（{code_txt}），非我方凭证问题，请稍后重试。"
                 f"\nℹ️ 已连续 {streak} 轮上游不可达。")
        if streak >= UPSTREAM_STREAK_THRESHOLD and not alerted:
            text = (f"🚨 连续 {streak} 轮上游面板不可达（{code_txt}），"
                    f"源站可能长期故障，请人工核查。\n\n") + text
            alerted = True
            log(f"  🚨 连续 {streak} 轮上游不可达，升级告警（本轮只发一次）")

    st.update(upstream_streak=streak, upstream_alerted=alerted,
              last_run=time.strftime("%Y-%m-%d %H:%M:%S"), last_worst=worst.value)
    _save_state(st)

    notify.send(text)
    return exit_code


class CaptchaRequired(RuntimeError):
    """面板登录接口要求 Cloudflare Turnstile，纯 API 登录在 CI 里过不了。"""


def log(msg: str) -> None:
    print(msg, flush=True)


# ---------------------------------------------------------------- 登录

def _who_am_i(r) -> str:
    try:
        return (r.json().get("attributes") or {}).get("username", "") or ""
    except Exception:
        return ""


def login_api_key():
    """纯 Bearer 认证。返回 session，失败返回 None。

    ⚠️ 绝不能给这个 session 加 X-Requested-With / Referer / X-XSRF-TOKEN：
       一带上，Sanctum 就把请求当浏览器会话走 CSRF，401 直接变 419
       （2026-11-23 实测：裸 Bearer → 401 Unauthenticated，带 XHR → 419）。
    """
    s = build_session()
    s.headers["Authorization"] = f"Bearer {API_KEY}"
    r = request(s, "GET", f"{PANEL}/api/client/account")
    if r.status_code == 200:
        log(f"✅ API Key 認證成功: {_who_am_i(r)}（無登錄、無 Turnstile、無 cookie）")
        return s

    log(f"⚠️ API Key 認證失敗 → HTTP {r.status_code}")
    log(f"   URL: {PANEL}/api/client/account")
    log(f"   detail: {(r.text or '')[:300]}")
    if r.status_code == 419:
        log("   ⚠️ 419 是請求形狀錯（帶了 X-Requested-With / Referer / XSRF），"
            "API Key 模式必須裸 Bearer —— 檢查是否有人給 session 加了瀏覽器頭")
    return None


def login_cookie():
    """舊路徑：cookie 模式（JEXACTYL_SESSION）。返回 session 或 None。"""
    cookie = env.get("JEXACTYL_SESSION", "")
    if not cookie:
        return None
    s = build_session()
    s.cookies.set("jexactyl_session", cookie, domain="panel.host-ship.com", path="/")
    r = request(s, "GET", f"{PANEL}/api/client/account")
    if r.status_code == 200:
        log(f"✅ cookie 登入成功: {_who_am_i(r)}")
        return s
    log(f"⚠️ cookie 模式驗證失敗 → HTTP {r.status_code}")
    log(f"   detail: {(r.text or '')[:300]}")
    return None


def login_password():
    """最後嘗試：帳密。Turnstile 開著時固定 400 captcha。"""
    if not (USER and PASS):
        return None
    s = build_session()
    r = request(s, "GET", f"{PANEL}/sanctum/csrf-cookie")
    if r.status_code not in (200, 204):
        raise RuntimeError(f"sanctum/csrf-cookie → HTTP {r.status_code}")

    xsrf = urllib.parse.unquote(s.cookies.get("XSRF-TOKEN", ""))
    if not xsrf:
        raise RuntimeError("没有拿到 XSRF-TOKEN")

    r = request(s, "POST", f"{PANEL}/auth/login",
                json={"user": USER, "password": PASS},
                headers={"X-XSRF-TOKEN": xsrf, "Referer": f"{PANEL}/auth/login"},
                allow_redirects=False)
    if r.status_code != 200:
        body = (r.text or "").strip()
        log(f"❌ 登录失败 → HTTP {r.status_code}")
        log(f"   URL: {PANEL}/auth/login")
        log(f"   请求字段: user, password（值不打印）| X-XSRF-TOKEN 长度={len(xsrf)}")
        log(f"   detail: {body[:500]}")
        if "captcha" in body.lower():
            raise CaptchaRequired(body[:500])
        raise RuntimeError(f"登录失败 → HTTP {r.status_code}: {body[:200]}")

    data = (r.json().get("data") or {}) if r.text else {}
    if not data.get("complete") and not data.get("user"):
        raise RuntimeError(f"登录未完成: {str(data)[:200]}")

    request(s, "GET", f"{PANEL}/")           # 走一趟首页，拿齐 session cookie
    s.headers["X-XSRF-TOKEN"] = urllib.parse.unquote(s.cookies.get("XSRF-TOKEN", "") or xsrf)
    log(f"✅ 登录成功: {(data.get('user') or {}).get('username', '')}")
    return s


def login():
    """按 API Key → cookie → 帳密 的順序認證，返回 (session, mode)。"""
    if API_KEY:
        s = login_api_key()
        if s is not None:
            return s, AUTH_API
        log("↩️ API Key 不可用，退回 cookie 模式")
    else:
        log("ℹ️ 未配置 HS_API_KEY，直接用 cookie / 帳密模式")

    s = login_cookie()
    if s is not None:
        return s, AUTH_COOKIE

    if USER and PASS:
        log("↩️ 改用帳密登入（PANEL_USER / PANEL_PASS）")
        s = login_password()
        if s is not None:
            return s, AUTH_PASSWORD

    raise RuntimeError(
        "所有認證方式都失敗：HS_API_KEY 無效/未配置、JEXACTYL_SESSION 已失效、"
        "帳密登入被 Turnstile 擋住。→ 請在面板 Account → API 建一枚 Client API Key，"
        "寫入 secret HS_API_KEY（純 HTTP 路徑，不受 cookie 壽命與 Turnstile 影響）"
    )


# ---------------------------------------------------------------- 续期

def get_server(s, server_id: str):
    r = request(s, "GET", f"{PANEL}/api/client/servers/{server_id}")
    if r.status_code != 200:
        return None, f"GET server → HTTP {r.status_code}: {(r.text or '')[:150]}"
    return (r.json().get("attributes") or {}), ""


def _xsrf_token(s) -> str:
    """2026-10-25：renew 係 web 路由，要 X-XSRF-TOKEN header（值係 XSRF-TOKEN cookie
    URL-decode 之後）；冇 cookie 就撈一次面板首頁種返。API Key 模式不需要。"""
    tok = ""
    try:
        tok = s.cookies.get("XSRF-TOKEN") or ""
    except Exception:
        tok = ""
    if not tok:
        try:
            request(s, "GET", f"{PANEL}/")
            tok = s.cookies.get("XSRF-TOKEN") or ""
        except Exception:
            tok = ""
    return urllib.parse.unquote(tok) if tok else ""


def _renew_headers(s, mode: str) -> dict:
    """API Key 模式只发 Content-Type；浏览器模式才带那三个头。

    2026-11-23 实测：给這條路由帶 X-Requested-With / Referer / X-XSRF-TOKEN，
    就被 Sanctum 當瀏覽器會話走 CSRF，回 419 CSRF token mismatch；
    裸 Bearer 則是正常的 401/204。所以模式必須分開，不能共用一套頭。
    """
    hdr = {"Content-Type": "application/json"}
    if mode != AUTH_API:
        hdr["Referer"] = f"{PANEL}/server/{{sid}}"
        hdr["X-Requested-With"] = "XMLHttpRequest"
        hdr["X-XSRF-TOKEN"] = _xsrf_token(s)
    return hdr


def renew_server(s, server_id: str, mode: str) -> tuple[Outcome, str]:
    """发一次续期请求，返回 (Outcome, 说明)。"""
    hdr = _renew_headers(s, mode)
    if mode != AUTH_API:
        hdr["Referer"] = f"{PANEL}/server/{server_id}"
    r = request(s, "POST", f"{PANEL}/api/client/servers/{server_id}/renew",
                json={}, headers=hdr)

    if r.status_code in (200, 204):
        return Outcome.RENEWED, f"✅ 续约成功 (HTTP {r.status_code})"

    detail = ""
    try:
        detail = json.loads((r.text or "").strip())["errors"][0]["detail"]
    except Exception:
        detail = (r.text or "").strip()[:200]

    # 请求形状错（带了浏览器头）要说清楚，别混进「凭证错」。
    if r.status_code == 419:
        return Outcome.FAILED, (
            "❌ 419 CSRF token mismatch —— 請求形狀錯，不是憑證錯"
            f"（mode={mode}）：API Key 模式不能帶 X-Requested-With / Referer / XSRF"
        )

    # 已达上限 → 不是失败（站方訊息會寫 30 日或 14 日，兩種都見過）
    if r.status_code in (400, 422) and re.search(r"cannot add more than \d+ days", detail or "", re.I):
        return Outcome.ALREADY_MAX, f"⏭️ 已达续期上限（{detail}），无需再续 (HTTP {r.status_code})"
    return Outcome.FAILED, f"❌ 续约失败 (HTTP {r.status_code}): {detail}"


def _days_left(val) -> int | None:
    """面板 renewal 字段是「剩餘天數」整數（2026-11 實測 14/13），
    不是 ISO 日期；整數就直接用，其餘交給 renewkit 解析。"""
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val
    try:
        return int(str(val))
    except Exception:
        return days_left(val)


def read_renewal(s, server_id: str, delay: float = 2):
    """隔 delay 秒读回 renewal（读不到返回 None）。"""
    time.sleep(delay)
    attrs, err = get_server(s, server_id)
    if not attrs:
        log(f"  ⚠️ 续后读取失败: {err}")
        return None
    log(f"  续后 renewal: {attrs.get('renewal')} | renewable: {attrs.get('renewable')}")
    return attrs.get("renewal")


def renew_until_full(s, server_id: str, mode: str) -> tuple[Outcome, str, object]:
    """首次 POST（含面板 CD 重试），之后剩余天数不够就补点。"""
    outcome, msg = renew_server(s, server_id, mode)
    log(f"  {msg}")

    # 面板 CD: "You can renew again in N seconds"
    for _ in range(3):
        m = re.search(r"renew again in (\d+) seconds", msg, re.IGNORECASE)
        if outcome is Outcome.RENEWED or not m:
            break
        wait = min(int(m.group(1)) + 3, 300)
        log(f"  ⏳ 面板 CD: 等 {wait} 秒再重试...")
        time.sleep(wait)
        outcome, msg = renew_server(s, server_id, mode)
        log(f"  {msg}")

    if outcome is not Outcome.RENEWED:
        return outcome, msg, None

    new_exp = read_renewal(s, server_id)
    extra, prev_left = 0, None
    while True:
        left = _days_left(new_exp)
        if left is None:
            log("  ⏭️ 剩余天数读不到，不补点")
            break
        if left >= TOPUP_GOAL_DAYS:
            log(f"  ✅ 剩 {left} 日，已达目标 ({TOPUP_GOAL_DAYS} 日，面板封顶 14 日)")
            break
        if prev_left is not None and left <= prev_left:
            log(f"  ⏭️ 补点后无进展 ({prev_left} → {left})，停")
            break
        if extra >= TOPUP_MAX_EXTRA:
            log(f"  ⏭️ 已补 {extra} 次，停 (剩 {left} 日)")
            break

        extra += 1
        prev_left = left
        time.sleep(TOPUP_INTERVAL_S)
        o2, msg2 = renew_server(s, server_id, mode)
        log(f"  🔁 补点 {extra}/{TOPUP_MAX_EXTRA}: {msg2}")
        if o2 is Outcome.ALREADY_MAX:
            log("  ✅ 面板报已满，当成功")
            break
        if o2 is not Outcome.RENEWED:
            log(f"  ⚠️ 补点失败，收手: {(msg2 or '')[:120]}")
            break
        again = read_renewal(s, server_id)
        if again is not None:
            new_exp = again

    return Outcome.RENEWED, msg, new_exp


# ---------------------------------------------------------------- 主流程

def main() -> int:
    # 認證三選一即可：API Key / cookie / 帳密。全都沒有才報憑證缺失。
    if not API_KEY and not env.get("JEXACTYL_SESSION", "") and not (USER and PASS):
        report = RenewReport(SERVICE)
        report.add("凭证", Outcome.FAILED,
                   detail="缺少 HS_API_KEY / JEXACTYL_SESSION / PANEL_USER+PANEL_PASS")
        return finalize(report)

    log(f"🚀 {SERVICE} 续约 @ {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"面板: {PANEL} | 服务器: {SERVER_IDS} | dry_run={DRY_RUN} "
        f"| api_key={'有' if API_KEY else '无'} | cookie={'有' if env.get('JEXACTYL_SESSION') else '无'}")

    report = RenewReport(SERVICE)

    try:
        session, mode = login()
    except TransientError as exc:
        report.add("登录", Outcome.TRANSIENT, detail=str(exc))
        return finalize(report)
    except CaptchaRequired as exc:
        # 面板登录接口要 Turnstile，纯 API 过不了（假帐密也回同一个错，见 login_password 注释）。
        # 这条不是「凭证错」，别再让人去改密码；能给的就是换 cookie 或上 API Key。
        log("❌ 面板登录接口要求 Turnstile captcha，CI 环境无法通过")
        log(f"   detail: {str(exc)[:500]}")
        report.add("登录", Outcome.FAILED,
                   detail="登录接口要 Turnstile captcha（CI 过不了）→ 请配置 HS_API_KEY "
                          "（面板 Account → API 建 Client API Key），或提供新的 "
                          "JEXACTYL_SESSION cookie")
        return finalize(report)
    except Exception as exc:
        log(f"❌ 登录异常: {type(exc).__name__}: {str(exc)[:500]}")
        report.add("登录", Outcome.FAILED, detail=str(exc)[:500])
        return finalize(report)

    log(f"🔐 认证模式: {mode}")

    for sid in SERVER_IDS:
        log(f"── 服务器 {sid} ──")
        try:
            attrs, err = get_server(session, sid)
        except TransientError as exc:
            report.add(sid, Outcome.TRANSIENT, detail=str(exc))
            continue

        if err:
            log(f"  {err}")
            report.add(sid, Outcome.FAILED, detail=err[:150])
            continue

        name = attrs.get("name", sid)
        renewal = attrs.get("renewal")
        renewable = attrs.get("renewable")
        log(f"  名称: {name} | renewable={renewable} | renewal={renewal}")

        if not renewable:
            report.add(name, Outcome.SKIPPED, expire=renewal, detail="暂不可续 (renewable=false)")
            continue

        if DRY_RUN:
            report.add(name, Outcome.SKIPPED, expire=renewal, detail="dry-run：未真正续约")
            continue

        try:
            outcome, msg, new_exp = renew_until_full(session, sid, mode)
        except TransientError as exc:
            report.add(name, Outcome.TRANSIENT, expire=renewal, detail=str(exc))
            continue

        if outcome is Outcome.RENEWED:
            log(f"  {msg} | 新 renewal={new_exp}")
            # 真成功 = 拿到新到期日且确实往后推了；读不到 / 没变化 只能算「结果未确认」，
            # 不能再像旧码那样报成功（那等于把"没验证"当成"续上了"）。
            if new_exp is None:
                report.add(name, Outcome.UNKNOWN, expire=renewal,
                           detail="面板返回成功，但续后读不到到期日，无法确认")
            elif renewal and str(new_exp) == str(renewal):
                report.add(name, Outcome.UNKNOWN, expire=new_exp,
                           detail=f"面板返回成功，但到期日未变化（{renewal}）")
            else:
                report.add(name, Outcome.RENEWED, expire=new_exp or renewal)
        elif outcome is Outcome.ALREADY_MAX:
            report.add(name, Outcome.ALREADY_MAX, expire=renewal)
        else:
            clean = re.sub(r"^[❌⏭️]\s*", "", msg or "")[:120]
            report.add(name, Outcome.FAILED, expire=renewal, detail=clean)

    return finalize(report)


if __name__ == "__main__":
    sys.exit(main())
