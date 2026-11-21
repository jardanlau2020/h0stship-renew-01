#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Host-Ship 登录并导出 cookie —— 探针的可用版。

探针 run 44895479028 已验证：账密 + 系统级鼠标点 Turnstile → 一次点击过盾
（token_len=709）→ 登录成功 → 拿到 4 个 cookie。

本脚本只做一件事：登录成功后，把可直接粘进 secret 的 cookie 串打印出来。
不写 secret（那需要 PAT），不改 renew.py，不动业务。

用法：workflow_dispatch 手动跑一次，复制输出的 `JEXACTYL_SESSION=...` 那行。
"""
from __future__ import annotations

import json
import os
import sys
import time
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


def main():
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

        cookies = {c["name"]: c["value"] for c in sb.driver.get_cookies()}
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

        # 机器可读摘要（不含值）
        print("PROBE_RESULT_JSON " + json.dumps({
            "ok": True,
            "cookie_names": sorted(cookies.keys()),
            "has_session": bool(sess),
            "has_remember": bool(rem),
            "session_len": len(sess),
        }), flush=True)
        return 0


if __name__ == "__main__":
    sys.exit(main())
