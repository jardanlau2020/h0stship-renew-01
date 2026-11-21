#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Host-Ship 登录并导出 cookie —— 探针的可用版 + cookie 到期巡检。

探针 run 44895479028 已验证：账密 + 系统级鼠标点 Turnstile → 一次点击过盾
（token_len=709）→ 登录成功 → 拿到 4 个 cookie。

两种模式：
  python login_refresh.py           登录并导出 cookie（workflow_dispatch）
  python login_refresh.py --check   只读巡检当前 secret 里的 cookie，快到期就发 TG

本脚本不写 secret（那需要 PAT），不改 renew.py，不动业务。

为什么要有 --check：jexactyl_session 是 Laravel 加密 cookie，值里读不出到期时间，
浏览器侧也是 session cookie（无 expiry 属性）；实测寿命 6 日。所以到期时间只能用
「上次成功刷新的时刻 + COOKIE_TTL_DAYS」推算。刷新时刻落 .cookie-state.json，
由 workflow 用 actions/cache 跨 run 传递。巡检任务每天跑一次，剩不到
COOKIE_WARN_DAYS（默认 2 日）或 cookie 已经失效，就发 TG 叫人去重跑 dispatch。
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

PANEL = (os.getenv("PANEL_URL") or "https://panel.host-ship.com").rstrip("/")
USER = os.getenv("PANEL_USER", "")
PASSWORD = os.getenv("PANEL_PASS", "")

TS_IFRAME = 'iframe[src*="challenges.cloudflare.com"]'
X_SUBMIT = "//button[@type='submit' or contains(normalize-space(),'Sign In')]"

# 只回写这两个。冷王 2026-11-21 指出：
#   · cf_clearance 是 CF 的 WAF 通行证，绑 IP + UA，寿命几十分钟到几小时。
#     写进 cookie 只会污染「cookie 还有效」的判断——换 IP 跑必然失效，脚本却以为还活着。
#   · XSRF-TOKEN 每次登录都会重新下发，不用存。
WANT = ("jexactyl_session", "remember_web_")

# 过盾的硬判据（冷王从 run 44895479028 的 body_hint 里提炼的）：
#   初始   "... Complete the security check ..."   ← 这句在 = 还没过
#   过盾后 "... Sign In ..."                       ← 这句消失 = 过了
# 比 btn_enabled 可靠：Sign In 按钮本来就是过盾后才出现，等于在问同一件事。
SEC_CHECK_TEXT = "Complete the security check"

# ── cookie 有效期巡检 ──────────────────────────────────────────────────
# 6 日：账密登录后拿到的 jexactyl_session 实测寿命。站方若改 TTL，改这个数即可。
COOKIE_TTL_DAYS = float(os.getenv("COOKIE_TTL_DAYS", "6"))
# 剩不到这么多天就报警。cron 压到 3 日一轮，留 2 日余量正好卡在漏跑一轮也还活着。
COOKIE_WARN_DAYS = float(os.getenv("COOKIE_WARN_DAYS", "2"))
STATE_FILE = os.getenv("COOKIE_STATE_FILE", ".cookie-state.json")
ACCOUNT_API = "/api/client/account"

# runner 是 UTF-8，Windows 本地控制台是 GBK —— 不兜底的话 log 里的 emoji 直接抛
# UnicodeEncodeError，把「只是打日志」变成脚本崩溃。
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def log(*a):
    print(f"[{datetime.now():%H:%M:%S}]", *a, flush=True)


def ts_token(sb) -> str:
    try:
        return sb.execute_script(
            "var e=document.querySelector('input[name=\"cf-turnstile-response\"]');"
            "return e?e.value:'';") or ""
    except Exception:
        return ""


def btn_enabled(sb, xpath) -> bool:
    try:
        el = sb.find_element(xpath, by="xpath", timeout=1)
        return el.is_enabled() and el.get_attribute("disabled") is None
    except Exception:
        return False


def click_turnstile(sb):
    """面板的 Turnstile 是 invisible 模式（ts_iframes 恒 0），直接系统鼠标点。"""
    try:
        sb.uc_gui_click_captcha()
    except Exception as e:
        log("uc_gui_click_captcha 异常：", str(e).splitlines()[0][:200])


def security_check_gone(sb) -> bool:
    """`Complete the security check` 这句消失 = 过盾成功。"""
    try:
        body = sb.execute_script(
            "return document.body ? document.body.innerText : '';") or ""
        return SEC_CHECK_TEXT not in body
    except Exception:
        return False


def pass_turnstile(sb, timeout=60):
    """等过盾。判据双保险：token 非空 或 页面不再显示安全校验提示。

    冷王 2026-11-21：这次 detach=False + uc_gui_click_captcha() 一次就过，
    所以不搬 MARK_TS_JS 算坐标那套，也不调 rerender_detached 里的 sb.reconnect()
    ——那正是 orihost 上杀死 chromedriver 的同一个调用。
    """
    start, clicks = time.time(), 0
    while time.time() - start < timeout:
        tok = ts_token(sb)
        if tok:
            log(f"Turnstile 已通过（点击 {clicks} 次），token_len={len(tok)}")
            return tok
        if clicks > 0 and security_check_gone(sb):
            log(f"过盾判据命中：'{SEC_CHECK_TEXT}' 已消失（点击 {clicks} 次），"
                f"但 token 为空——以 token 为准继续等")
        if clicks < 4 and (clicks == 0 or time.time() - start > clicks * 15):
            click_turnstile(sb)
            clicks += 1
        sb.sleep(2)
    return ""


# ---------------------------------------------------------------- 状态文件

def load_state() -> dict:
    # utf-8-sig：Windows 侧写出来的状态文件可能带 BOM，用 utf-8 读会在 json.loads
    # 直接抛 "Unexpected UTF-8 BOM"，然后被下面 except 静默吞掉 —— 表现成「状态永远
    # 读不到、预警永远不触发」，最难查的那种静默失效。
    try:
        with open(STATE_FILE, encoding="utf-8-sig") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_state(data: dict) -> None:
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        log(f"状态已写入 {STATE_FILE}（只含时间戳与长度，不含 cookie 值）")
    except Exception as exc:
        log("状态写入失败（不影响主流程）：", str(exc)[:150])


# ---------------------------------------------------------------- 巡检

def probe_session(cookie: str, timeout: float = 20) -> tuple[bool, str, str]:
    """拿 cookie 打一次 /api/client/account：200 = 还活着。"""
    if not cookie:
        return False, "secret 里没有 JEXACTYL_SESSION", ""
    req = urllib.request.Request(
        PANEL + ACCOUNT_API,
        headers={
            "Cookie": f"jexactyl_session={cookie}",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (hostship-cookie-guard)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            if resp.status != 200:
                return False, f"HTTP {resp.status}", ""
            try:
                who = (json.loads(body).get("attributes") or {}).get("username") or ""
            except Exception:
                who = ""
            return True, "HTTP 200", who
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}", ""
    except Exception as exc:
        return False, f"请求异常 {str(exc)[:120]}", ""


def estimate_expiry(state: dict) -> tuple[float | None, str]:
    """推算 cookie 到期时刻（epoch 秒）。

    默认只用「上次刷新时刻 + TTL」，**不用**浏览器给的 expiry 属性：

      · 2026-11-21 run 44903281031 实测，登录后 jexactyl_session 的 expiry 属性只有
        12 小时（不是 6 日）——那是 Laravel 的滑动 session 寿命，不是真实死亡时刻。
      · 真实寿命来自历史：01 仓 11-15 12:16 续约成功 → 11-21 09:58 失败，隔 5.9 日。
        02 仓 11-08 成功 → 11-15 失败，隔 7 日窗口内同样失效。
      · 拿 12 小时去算，巡检会天天误报，预警就变成噪音。

    所以 expiry 属性只记进状态备查（cookie_expiry_raw），要启用就显式
    设 COOKIE_USE_BROWSER_EXPIRY=1。
    """
    if os.getenv("COOKIE_USE_BROWSER_EXPIRY", "0") == "1":
        exp = state.get("cookie_expiry_raw")
        if isinstance(exp, (int, float)) and exp > 0:
            return float(exp), "浏览器 cookie 自带 expiry（已手动启用）"
    issued = state.get("refreshed_at")
    if isinstance(issued, (int, float)) and issued > 0:
        return float(issued) + COOKIE_TTL_DAYS * 86400, f"上次刷新 + {COOKIE_TTL_DAYS:g} 日 TTL"
    return None, "无状态记录（还没有成功刷新过）"


def tg(text: str) -> bool:
    """发 TG。优先用 renew-kit 的 notify.send（上游现成实现，不重复写）。"""
    try:
        from renewkit.notify import send
        return send(text, parse_mode="HTML")
    except Exception as exc:
        log("renewkit 不可用，退回内置发送：", str(exc)[:150])

    token = os.getenv("TG_BOT_TOKEN") or os.getenv("TELEGRAM_TOKEN") or ""
    chat = os.getenv("TG_CHAT_ID") or os.getenv("TELEGRAM_CHAT_ID") or ""
    if not token or not chat:
        log("Telegram 未配置，跳过通知")
        return False
    data = urllib.parse.urlencode({
        "chat_id": chat, "text": text,
        "parse_mode": "HTML", "disable_web_page_preview": "true",
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage", data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            ok = json.loads(resp.read().decode("utf-8", "replace")).get("ok")
            log("Telegram 通知已发送" if ok else "Telegram 通知失败")
            return bool(ok)
    except Exception as exc:
        log("Telegram 通知异常：", str(exc)[:150])
        return False


def check_mode() -> int:
    """只读巡检：cookie 是否还活着 + 还剩几天，不达标就发 TG。"""
    state = load_state()
    cookie = os.getenv("JEXACTYL_SESSION", "")
    ok, detail, who = probe_session(cookie)
    exp, basis = estimate_expiry(state)
    now = time.time()
    left_days = (exp - now) / 86400 if exp else None

    log(f"面板: {PANEL}")
    log(f"cookie 探测: {'✅ 有效' if ok else '❌ 失效'}（{detail}{' / ' + who if who else ''}）")
    if exp:
        log(f"到期推算: {datetime.fromtimestamp(exp):%Y-%m-%d %H:%M} 本地时间 "
            f"（依据：{basis}），剩 {left_days:.2f} 日")
    else:
        log(f"到期推算: 未知（{basis}）")
    log(f"阈值: 剩 < {COOKIE_WARN_DAYS:g} 日 或 cookie 已失效 → 报警")

    reasons = []
    if not ok:
        reasons.append(f"cookie 已失效（{detail}）——续约必然失败，需要重跑 login-refresh 并更新 secret")
    if left_days is not None and left_days < COOKIE_WARN_DAYS:
        reasons.append(f"cookie 剩 {left_days:.2f} 日，低于 {COOKIE_WARN_DAYS:g} 日警戒线")

    print("PROBE_RESULT_JSON " + json.dumps({
        "ok": ok,
        "detail": detail,
        "username": who,
        "expiry_epoch": exp,
        "left_days": None if left_days is None else round(left_days, 2),
        "basis": basis,
        "warn_days": COOKIE_WARN_DAYS,
        "alert": bool(reasons),
    }), flush=True)

    if not reasons:
        log("✅ 巡检通过，不需要动作")
        return 0

    head = "🚨 Host-Ship cookie 失效" if not ok else "⚠️ Host-Ship cookie 快到期"
    body = "\n".join(f"• {r}" for r in reasons)
    tg(f"<b>{head}</b>\n{body}\n\n👉 处理：Actions → 「登录并导出 cookie」→ Run workflow，"
       f"把 cookies.txt 里的 JEXACTYL_SESSION 更新到 secret。\n"
       f"（{datetime.now():%Y-%m-%d %H:%M}）")
    log("已报警：" + "；".join(reasons))
    # 巡检只报不红：job 标红会掩盖真正的续约失败信号。
    return 0


# ---------------------------------------------------------------- 主流程

def main():
    if "--check" in sys.argv:
        return check_mode()

    if not USER or not PASSWORD:
        log("❌ 缺 PANEL_USER / PANEL_PASS")
        return 2

    from seleniumbase import SB

    log(f"面板: {PANEL}")
    log(f"平台={sys.platform} DISPLAY={os.environ.get('DISPLAY') or '（空）'}")
    kw = dict(uc=True, test=True, headless=False, locale_code="en",
              page_load_strategy="eager")

    with SB(**kw) as sb:
        try:
            sb.set_default_timeout(20)
        except Exception:
            pass
        try:
            sb.driver.window_handles
            log("✅ driver 健康检查通过")
        except Exception as e:
            log("❌ driver 起不来：", str(e).splitlines()[0][:200])
            return 3

        sb.uc_open(PANEL + "/auth/login")
        sb.sleep(6)

        try:
            sb.wait_for_element('input[type="password"]', timeout=40)
            sb.type('input[name="username"]', USER)
            sb.type('input[type="password"]', PASSWORD)
            log("已填入 username / password（值不打印）")
        except Exception as e:
            log("❌ 填表失败：", str(e).splitlines()[0][:200])
            try:
                sb.save_screenshot("login_fail.png")
            except Exception:
                pass
            return 4

        tok = pass_turnstile(sb, timeout=60)
        if not tok:
            log("❌ Turnstile 未拿到 token（60 秒）")
            try:
                sb.save_screenshot("login_fail.png")
            except Exception:
                pass
            return 5

        log("▶ 提交登录")
        try:
            sb.click(X_SUBMIT, by="xpath")
        except Exception as e:
            log("点击提交异常：", str(e).splitlines()[0][:200])

        end = time.time() + 40
        while time.time() < end and "/auth/login" in (sb.get_current_url() or ""):
            sb.sleep(1)

        url = sb.get_current_url() or ""
        log(f"提交后 URL: {url}")
        if "/auth/login" in url:
            log("❌ 登录失败（仍停在登录页）")
            try:
                sb.save_screenshot("login_fail.png")
            except Exception:
                pass
            return 6

        raw_cookies = sb.driver.get_cookies()
        cookies = {c["name"]: c["value"] for c in raw_cookies}
        log(f"✅ 登录成功，拿到 {len(cookies)} 个 cookie")

        sess = cookies.get("jexactyl_session", "")
        rem = next((v for k, v in cookies.items() if k.startswith("remember_web_")), "")

        # 冷王 2026-11-21 指出：GitHub 只 mask「job 启动时已注册的 secret 旧值」，
        # 这里是新值，不在 mask 表里 —— 直接 print 会以明文落在 Actions 日志 +
        # artifact（默认 90 天）。为了换掉一个可能过期的凭证，把新凭证明文存 90 天，
        # 是唯一一件「省 10 分钟、赔一个凭证」的事。
        # 所以：值只写文件（artifact retention-days: 1），日志里连 add-mask 都不用，
        # 因为压根不打印。
        if not sess:
            log(f"❌ 登录成功但没拿到 jexactyl_session，cookie 名可能变了："
                f"{sorted(cookies.keys())}")
            return 7

        with open("cookies.txt", "w", encoding="utf-8") as fh:
            fh.write(f"JEXACTYL_SESSION={sess}\n")
            if rem:
                fh.write(f"REMEMBER_WEB={rem}\n")
        try:
            os.chmod("cookies.txt", 0o600)
        except Exception:
            pass

        log("cookie 已写入 cookies.txt（只进 artifact，保留 1 天；不进日志）")
        log(f"   jexactyl_session len={len(sess)}")
        if rem:
            log(f"   remember_web len={len(rem)}")
        log(f"   全部 cookie 名：{sorted(cookies.keys())}")

        # 记下刷新时刻供每日巡检推算到期。浏览器给的 expiry 属性只当参考记下来
        # （它是 12 小时的滑动值，不是真实寿命，见 estimate_expiry 的注释）。
        # 只存时间戳和长度，不存 cookie 值 —— 状态文件要进 cache，不能带凭证。
        raw_expiry = None
        for c in raw_cookies:
            if c.get("name") in WANT and c.get("expiry"):
                raw_expiry = float(c["expiry"])
                break
        if raw_expiry:
            log(f"   浏览器给的 expiry 属性: {datetime.fromtimestamp(raw_expiry):%Y-%m-%d %H:%M}"
                f"（滑动值，只记录，不用于推算）")
        exp = time.time() + COOKIE_TTL_DAYS * 86400
        log(f"   到期推算: {datetime.fromtimestamp(exp):%Y-%m-%d %H:%M}"
            f"（刷新时刻 + {COOKIE_TTL_DAYS:g} 日 TTL）")
        save_state({
            "refreshed_at": time.time(),
            "cookie_expiry_raw": raw_expiry,
            "session_len": len(sess),
            "has_remember": bool(rem),
            "cookie_names": sorted(cookies.keys()),
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        })

        # 机器可读摘要（不含值）
        print("PROBE_RESULT_JSON " + json.dumps({
            "ok": True,
            "cookie_names": sorted(cookies.keys()),
            "has_session": bool(sess),
            "has_remember": bool(rem),
            "session_len": len(sess),
            "expiry_epoch": exp,
            "left_days": round((exp - time.time()) / 86400, 2),
        }), flush=True)
        return 0


if __name__ == "__main__":
    sys.exit(main())
