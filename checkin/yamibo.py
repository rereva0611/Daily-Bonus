# -*- coding: utf-8 -*-
# @File     : yamibo.py
# @Time     : 2021/04/07 15:48
# @Author   : Jckling

import os
import re
import sys
from urllib.parse import parse_qsl, urlsplit

from curl_cffi import requests as cffi_requests
from curl_cffi.requests.exceptions import RequestException
from lxml import html
from playwright.sync_api import sync_playwright

from checkin import net

# info
USERNAME = os.environ.get("YAMIBO_USERNAME")
PASSWORD = os.environ.get("YAMIBO_PASSWORD")
msg = []
sign_submission_started = False


class YamiboError(Exception):
    """A safe, user-facing Yamibo failure; never pass response or exception text."""

    def __init__(self, message, retryable=False):
        super().__init__(message)
        self.retryable = retryable


BASE_URL = "https://bbs.yamibo.com"

SESSION = cffi_requests.Session()

HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    "referer": "https://bbs.yamibo.com/",
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
}


def _raise_cloudflare_challenge(response, stage):
    """Recognize a challenge, not merely a Cloudflare-served normal page."""
    headers = {str(name).lower(): str(value).strip().lower()
               for name, value in response.headers.items()}
    challenge_header = headers.get("cf-mitigated") == "challenge"
    challenge_script = bool(re.search(r"cf-chl-|/cdn-cgi/challenge-platform", response.text, re.I))
    challenge_title = bool(re.search(
        r"<title>\s*(?:Just a moment(?:\.{3})?|Attention Required!\s*\|\s*Cloudflare)\s*</title>",
        response.text, re.I,
    ))
    if challenge_header or (challenge_script and challenge_title):
        raise YamiboError(f"{stage}遭遇 Cloudflare 安全验证，无法确认签到状态")


def _validate_response(response, stage, allow_login_page=False):
    """Reject transport/authentication error pages before the existing parser."""
    _raise_cloudflare_challenge(response, stage)
    if not 200 <= response.status_code < 300:
        raise YamiboError(f"{stage}返回 HTTP {response.status_code}，无法确认签到状态")
    if allow_login_page:
        return
    parts = urlsplit(str(getattr(response, "url", "")))
    query = dict(parse_qsl(parts.query))
    login_url = parts.path.endswith("/member.php") and query.get("action") == "login"
    login_form = bool(re.search(
        r"<form\b[^>]*(?:name\s*=\s*[\"']login[\"']|id\s*=\s*[\"']loginform(?:_[^\"']*)?[\"'])",
        response.text, re.I,
    ))
    login_prompt = "需要先登录" in response.text or "请先登录" in response.text
    if login_url or login_form or login_prompt:
        raise YamiboError("登录状态失效，网站返回登录页面或登录提示")


def solve_waf():
    """Ensure the forum is reachable: fast path on 200, else solve the challenge in a real browser."""
    r = SESSION.get(
        f"{BASE_URL}/forum.php",
        headers=HEADERS,
        impersonate="chrome",
        timeout=15,
    )
    _raise_cloudflare_challenge(r, "论坛页面")
    if r.status_code == 200:
        return True

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent=HEADERS["user-agent"],
        )
        page = context.new_page()
        page.goto(f"{BASE_URL}/forum.php", wait_until="networkidle", timeout=30000)
        cookies = context.cookies()
        browser.close()

    nox_cookie = next((c for c in cookies if c["name"] == "nox_jst_v1"), None)
    if nox_cookie:
        SESSION.cookies.set("nox_jst_v1", nox_cookie["value"], domain="bbs.yamibo.com")
        return True
    return False


def login():
    """Login via Discuz member.php and return True if successful."""
    global msg

    if not net.open_route(SESSION, f"{BASE_URL}/forum.php", impersonate="chrome"):
        msg.append({"name": "登录信息", "value": "无法连接网站"})
        raise YamiboError("无法连接网站", retryable=True)

    if not solve_waf():
        msg.append({"name": "登录信息", "value": "WAF 挑战失败"})
        return False

    # Step 1: GET login page to extract formhash and loginhash
    r = SESSION.get(
        f"{BASE_URL}/member.php",
        headers=HEADERS,
        params={
            "mod": "logging",
            "action": "login",
            "infloat": "yes",
            "frommessage": "",
            "inajax": "1",
            "ajaxtarget": "messagelogin",
        },
        impersonate="chrome",
    )

    _validate_response(r, "登录页面", allow_login_page=True)

    formhash_match = re.search(r'name="formhash"\s+value="([a-f0-9]+)"', r.text)
    loginhash_match = re.search(r'loginhash=([a-zA-Z0-9]+)', r.text)

    if not formhash_match:
        msg.append({"name": "登录信息", "value": "登录失败，无法获取 formhash"})
        return False

    formhash = formhash_match.group(1)
    loginhash = loginhash_match.group(1) if loginhash_match else ""

    # Step 2: POST login
    r2 = SESSION.post(
        f"{BASE_URL}/member.php",
        headers={
            **HEADERS,
            "content-type": "application/x-www-form-urlencoded",
        },
        params={
            "mod": "logging",
            "action": "login",
            "loginsubmit": "yes",
            "frommessage": "",
            "loginhash": loginhash,
            "inajax": "1",
        },
        data={
            "formhash": formhash,
            "referer": f"{BASE_URL}/forum.php",
            "username": USERNAME,
            "password": PASSWORD,
            "questionid": "0",
            "answer": "",
            "cookietime": "2592000",
        },
        impersonate="chrome",
    )

    _validate_response(r2, "登录响应", allow_login_page=True)

    if "succeedhandle" in r2.text or "succeed" in r2.text:
        msg.append({"name": "登录信息", "value": "登录成功"})
        return True
    elif "登录失败" in r2.text:
        msg.append({"name": "登录信息", "value": "登录失败，请检查认证信息"})
        return False
    else:
        msg.append({"name": "登录信息", "value": "登录失败，网站未返回明确成功结果"})
        return False


def get_sign_page():
    """Fetch sign page.

    Returns (sign_hash, already_signed, page_text) or (None, None, None) if not logged in.
    """
    url = f"{BASE_URL}/plugin.php?id=zqlj_sign"
    r = SESSION.get(url, headers=HEADERS, impersonate="chrome")

    _validate_response(r, "签到页面")

    global msg
    if "需要先登录" in r.text:
        msg.append({"name": "登录信息", "value": "登录失败，Cookie 可能已经失效"})
        return None, None, None

    sign_match = re.search(r'sign=([a-f0-9]+)', r.text)
    sign_hash = sign_match.group(1) if sign_match else None
    btn_match = re.search(r'class="btna"[^>]*>([^<]+)<', r.text)
    btn_text = btn_match.group(1).strip() if btn_match else ""

    if not btn_text and "我的打卡动态" not in r.text:
        msg.append({"name": "签到信息", "value": "页面被拦截，无法获取签到状态"})
        return None, None, None

    already_signed = "今日已打卡" in btn_text and "点击打卡" not in btn_text

    return sign_hash, already_signed, r.text


def check_in(sign_hash):
    """Perform sign-in by visiting the sign URL with the one-time hash."""
    global sign_submission_started
    sign_submission_started = True
    url = f"{BASE_URL}/plugin.php?id=zqlj_sign&sign={sign_hash}"
    r = SESSION.get(url, headers=HEADERS, impersonate="chrome")

    _validate_response(r, "签到请求")

    global msg
    if "打卡成功" in r.text:
        msg.append({"name": "签到信息", "value": "签到成功"})
        return True, r.text
    elif "打过卡" in r.text:
        msg.append({"name": "签到信息", "value": "今日已签到"})
        return True, r.text
    elif "需要先登录" in r.text:
        msg.append({"name": "签到信息", "value": "登录失败，Cookie 可能已经失效"})
        return False, r.text
    else:
        msg.append({"name": "签到信息", "value": "签到失败，未能从页面获取结果"})
        return False, r.text


def query_stats(page_text):
    """Query sign stats from sign page HTML and credit info from credit page."""
    global msg

    stats_map = {
        "最近打卡": "签到时间",
        "本月打卡": "本月签到",
        "连续打卡": "连续签到",
        "累计打卡": "累计签到",
        "最近奖励": "最近奖励",
    }
    for kw, name in stats_map.items():
        match = re.search(rf'{kw}：([^<]+)', page_text)
        if match:
            msg.append({"name": name, "value": match.group(1)})

    url = f"{BASE_URL}/home.php?mod=spacecp&ac=credit"
    r = SESSION.get(url, headers=HEADERS, impersonate="chrome")
    _validate_response(r, "账户信息")
    tree = html.fromstring(r.content)
    items = tree.xpath('//ul[@class="creditl mtm bbda cl"]/li')

    credit = {}
    for item in items:
        text = item.text_content().strip()
        match = re.match(r'(\S+):\s*(\S+)', text)
        if match:
            name, value = match.group(1), match.group(2)
            if name not in credit:
                credit[name] = value

    if credit:
        parts = [f"{k} {v}" for k, v in credit.items()]
        msg.append({"name": "账户余额", "value": "，".join(parts)})
    else:
        msg.append({"name": "账户余额", "value": "查询余额失败"})


def main():
    global msg, sign_submission_started
    msg = []
    sign_submission_started = False
    if not USERNAME or not PASSWORD:
        raise YamiboError("未配置 Yamibo 登录信息")

    try:
        if not login():
            raise YamiboError("登录失败，未能确认认证成功")

        sign_hash, already_signed, page_text = get_sign_page()
        if already_signed is None:
            raise YamiboError("无法获取签到状态")
        if not already_signed:
            if not sign_hash:
                raise YamiboError("未获取签到 hash，不能确认已签到")
            # Once submitted, transport failures may hide a completed sign-in.
            # The runner must never replay the entire operation after this point.
            sign_submission_started = True
            succeeded, _ = check_in(sign_hash)
            if not succeeded:
                raise YamiboError("签到失败或结果不明确，停止自动重试")
        else:
            msg.append({"name": "签到信息", "value": "今日已签到，无需重复签到"})
    except RequestException:
        if sign_submission_started:
            raise YamiboError("签到请求结果不明确，停止自动重试") from None
        raise YamiboError("签到前网络请求失败", retryable=True) from None

    # Sign-in is confirmed. Supplementary queries cannot turn it into a retry.
    try:
        if sign_submission_started:
            r2 = SESSION.get(
                f"{BASE_URL}/plugin.php?id=zqlj_sign",
                headers=HEADERS,
                impersonate="chrome",
            )
            _validate_response(r2, "签到状态刷新")
            page_text = r2.text
        query_stats(page_text)
    except Exception:
        msg.append({"name": "统计信息", "value": "签到已确认，附加信息查询失败"})

    return "\n".join([f"{one.get('name')}: {one.get('value')}" for one in msg])


if __name__ == "__main__":
    print(" Yamibo 签到开始 ".center(60, "="))
    exit_code = 0
    try:
        print(main())
    except YamiboError as error:
        print(f"Yamibo 失败：{error}")
        exit_code = 1
    except Exception:
        print("Yamibo 发生未预期异常，停止自动重试")
        exit_code = 1
    print(" Yamibo 签到结束 ".center(60, "="), "\n")
    sys.exit(exit_code)
