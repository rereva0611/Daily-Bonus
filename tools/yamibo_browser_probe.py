"""Read-only authenticated diagnostic, including a constrained WAF browser.

Run python tools/yamibo_browser_probe.py --from-env in Actions. It never submits
sign-in rewards, queries account statistics, or sends notifications.
"""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from checkin import yamibo

spec = importlib.util.spec_from_file_location("safe_probe", ROOT / "tools/yamibo_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
browser_state = {"cookies": [], "blocked_requests": 0}


def emit(event):
    print(json.dumps(event, ensure_ascii=False), flush=True)


def allowed_browser_request(method, url, kind):
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return False
    if port not in (None, 443):
        return False
    query = dict(parse_qsl(p.query))
    if (method != "GET" or p.scheme != "https" or p.hostname != "bbs.yamibo.com"
            or p.username or p.password or "sign" in query):
        return False
    if kind == "document":
        return p.path in {"/", "/forum.php"} and not query
    return kind in {"script", "stylesheet", "image", "font"} and p.path not in {
        "/member.php", "/plugin.php", "/home.php", "/api.php"
    }


assert allowed_browser_request("GET", "https://bbs.yamibo.com/forum.php", "document")
assert not allowed_browser_request("GET", "https://bbs.yamibo.com/plugin.php?id=zqlj_sign&sign=abc", "document")
assert not allowed_browser_request("POST", "https://bbs.yamibo.com/member.php", "document")
assert not allowed_browser_request("GET", "https://example.invalid/a.js", "script")


class PageProxy:
    def __init__(self, page):
        self.page = page

    def goto(self, url, **kwargs):
        response = self.page.goto(url, **kwargs)
        current = SimpleNamespace(text=self.page.content(), status_code=response.status if response else 0,
                                  url=self.page.url, headers=response.headers if response else {})
        emit(probe.summarize(current, "waf_browser_page"))
        return response


class ContextProxy:
    def __init__(self, context):
        self.context = context
        def route_request(route):
            request = route.request
            if allowed_browser_request(request.method, request.url, request.resource_type):
                route.continue_()
            else:
                browser_state["blocked_requests"] += 1
                route.abort()
        context.route("**/*", route_request)

    def new_page(self):
        return PageProxy(self.context.new_page())

    def cookies(self):
        cookies = self.context.cookies()
        browser_state["cookies"] = cookies
        emit({"stage": "waf_browser_storage", "cookie_count": len(cookies),
              "expected_waf_cookie_present": any(c["name"] == "nox_jst_v1" for c in cookies),
              "blocked_requests": browser_state["blocked_requests"]})
        return cookies


class BrowserProxy:
    def __init__(self, browser):
        self.browser = browser

    def new_context(self, **kwargs):
        kwargs["service_workers"] = "block"
        return ContextProxy(self.browser.new_context(**kwargs))

    def close(self):
        self.browser.close()


original_factory = yamibo.sync_playwright


class ManagerProxy:
    def __enter__(self):
        self.manager = original_factory()
        p = self.manager.__enter__()
        def launch(**kwargs):
            return BrowserProxy(p.chromium.launch(**kwargs))
        return SimpleNamespace(chromium=SimpleNamespace(launch=launch))

    def __exit__(self, *args):
        return self.manager.__exit__(*args)


import argparse
import getpass
import os

def run_authenticated(username, password, publish):
    global emit
    old_emit = emit
    records = []
    def record(value):
        records.append(value)
        publish(value)
    emit = record
    original_session = yamibo.SESSION
    old_username, old_password = yamibo.USERNAME, yamibo.PASSWORD
    old_factory = yamibo.sync_playwright
    original_check_in = yamibo.check_in
    original_stats = yamibo.query_stats
    def forbidden_action(*args, **kwargs):
        raise probe.UnsafeProbeRequest("Diagnostic cannot submit sign or query stats")
    yamibo.SESSION = probe.ReadOnlySession(original_session, emit)
    yamibo.sync_playwright = ManagerProxy
    yamibo.USERNAME, yamibo.PASSWORD = username, password
    yamibo.check_in = yamibo.query_stats = forbidden_action
    browser_state["cookies"] = []
    browser_state["blocked_requests"] = 0
    try:
        success = yamibo.login()
        emit({"stage":"original_login_result", "reported_success":success})
        if not success:
            return 1
        sign_hash, already_signed, _ = yamibo.get_sign_page()
        emit({"stage":"original_sign_parser", "hash_present":sign_hash is not None,
              "already_signed":already_signed, "sign_submission_attempted":False})
        sign_records = [r for r in records if r.get("stage") == "sign_page"]
        verified = bool(sign_records and sign_records[-1].get("classification") in {"ready", "already_signed"})
        emit({"stage":"verification", "authenticated_page_verified":verified})
        return 0 if verified and (already_signed is True or sign_hash is not None) else 1
    except Exception as error:
        emit({"stage":"authenticated_flow_result", "error_type":type(error).__name__,
              "sign_submission_attempted":False})
        return 1
    finally:
        yamibo.SESSION = original_session
        yamibo.sync_playwright = old_factory
        yamibo.check_in = original_check_in
        yamibo.query_stats = original_stats
        yamibo.USERNAME, yamibo.PASSWORD = old_username, old_password
        browser_state["cookies"] = []
        emit = old_emit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-env", action="store_true")
    args = parser.parse_args()
    if args.from_env:
        username = os.environ.get("YAMIBO_USERNAME")
        password = os.environ.get("YAMIBO_PASSWORD")
        if not username or not password:
            emit({"stage":"setup", "error":"credentials_not_configured"})
            return 2
    else:
        username = getpass.getpass("百合会用户名（输入不显示）: ")
        password = getpass.getpass("百合会密码（输入不显示）: ")
    try:
        return run_authenticated(username, password, emit)
    finally:
        username = password = None


if __name__ == "__main__":
    raise SystemExit(main())
