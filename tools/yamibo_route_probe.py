"""Metadata-only authenticated route probe; never claims or submits a reward.

Install beside the reviewed yamibo_probe.py and run:
  uv run --frozen --python 3.13 python tools/yamibo_route_probe.py --from-env
Only the exact sign page is navigated in the diagnostic Chromium context.
All redirects, dynamic assets, static queries, workers, and WebSockets are blocked.
"""
import argparse
import contextlib
import getpass
from http.cookiejar import Cookie
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("yamibo_route_safe_base", ROOT / "tools/yamibo_probe.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
SIGN_URL = base.ORIGIN + "/plugin.php?id=zqlj_sign"
COOKIE_DOMAINS = {"bbs.yamibo.com", ".bbs.yamibo.com", "yamibo.com", ".yamibo.com"}
DENIAL_TITLES = {"403 Forbidden", "Access Denied", "Forbidden", "访问被拒绝", "安全验证",
                 "Just a moment...", "Attention Required! | Cloudflare"}
SERVERS = {"cloudflare", "nginx", "openresty", "tengine", "yunjiasu-nginx", "yunjiasu", "ddos-guard"}
STATIC_EXTENSIONS = {"script": {".js"}, "stylesheet": {".css"},
                     "image": {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico"},
                     "font": {".woff", ".woff2", ".ttf", ".otf", ".eot"}}


def summarize(response, stage):
    result = base.summarize(response, stage)
    body = response.text
    markers = base.PageMarkers()
    markers.feed(body)
    title = " ".join(markers.title.split())
    if title in DENIAL_TITLES:
        result.update(title=title, title_omitted=False)
    headers = {str(key).lower(): str(value).lower() for key, value in response.headers.items()}
    server = headers.get("server", "")
    result.update(
        access_denied_marker=bool(re.search(r"access\s+denied|403\s+forbidden|拒绝访问|访问被拒绝|请求被拦截", body, re.I)),
        verification_marker=bool(re.search(r"安全验证|人机验证|verify you are human|cf-chl-", body, re.I)),
        nox_marker=bool(re.search(r"nox_jst_v1|/_nox/", body, re.I)),
        baidu_marker=bool(re.search(r"百度云加速|yunjiasu", body, re.I)),
        cloudflare_marker=bool(re.search(r"cf-chl-|challenges\.cloudflare\.com", body, re.I)),
        server_provider=server if server in SERVERS else "other",
        cloudflare_header_present=bool("cf-ray" in headers or headers.get("cf-mitigated") == "challenge"),
    )
    result["authenticated_sign_page_readable"] = bool(
        result["classification"] in {"ready", "already_signed"}
        and not result["access_denied_marker"] and not result["verification_marker"]
    )
    return result


def allowed_browser_request(method, url, kind):
    try:
        parts = urlsplit(url)
        if (method != "GET" or parts.scheme != "https" or parts.hostname != "bbs.yamibo.com"
                or parts.username or parts.password or parts.fragment or parts.port not in (None, 443)):
            return False
        query = parse_qsl(parts.query, keep_blank_values=True)
        if kind == "document":
            return ((parts.path in {"/", "/forum.php"} and not parts.query)
                    or (parts.path == "/plugin.php" and query == [("id", "zqlj_sign")]))
        path = parts.path
        if (parts.query or "%" in path or "\\" in path or "//" in path
                or any(part in {".", ".."} for part in path.split("/"))):
            return False
        return (path.startswith(("/static/", "/data/cache/"))
                and Path(path).suffix.lower() in STATIC_EXTENSIONS.get(kind, set()))
    except (TypeError, ValueError):
        return False


def install_browser_guard(context, page, state):
    """Use Chromium transport; stop redirects at the response pause before a hop."""
    def route_request(route):
        try:
            request = route.request
            allowed = (request.frame.page is page and allowed_browser_request(
                request.method, request.url, request.resource_type))
        except Exception:
            allowed = False
        if allowed:
            route.continue_()
        else:
            state["blocked_requests"] += 1
            route.abort()
    context.route("**/*", route_request)
    context.route_web_socket("**/*", lambda socket: socket.close())
    cdp = context.new_cdp_session(page)
    def response_paused(event):
        request_id = event["requestId"]
        try:
            if 300 <= event.get("responseStatusCode", 0) < 400:
                state["blocked_redirects"] += 1
                cdp.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
            else:
                cdp.send("Fetch.continueResponse", {"requestId": request_id})
        except Exception:
            state["guard_failed"] = True
            context.close()
    cdp.on("Fetch.requestPaused", response_paused)
    cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Response"}]})


def valid_cookie(domain, name, value, path):
    return (domain in COOKIE_DOMAINS and isinstance(name, str)
            and bool(re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name))
            and isinstance(value, str) and not re.search(r"[\x00-\x1f\x7f]", value)
            and isinstance(path, str) and path.startswith("/")
            and not re.search(r"[\x00-\x1f\x7f]", path))


def browser_cookies(session):
    result = []
    for cookie in session.cookies.jar:
        if not valid_cookie(cookie.domain, cookie.name, cookie.value, cookie.path):
            continue
        item = {"name": cookie.name, "value": cookie.value, "domain": cookie.domain,
                "path": cookie.path, "secure": bool(cookie.secure),
                "httpOnly": cookie.has_nonstandard_attr("HttpOnly")}
        if cookie.expires is not None and cookie.expires > 0:
            item["expires"] = float(cookie.expires)
        same_site = cookie.get_nonstandard_attr("SameSite")
        if same_site in {"Strict", "Lax", "None"}:
            item["sameSite"] = same_site
        result.append(item)
    return result


def copy_browser_cookies(session, cookies):
    count = 0
    for item in cookies:
        domain, name, value, path = (item.get(key) for key in ("domain", "name", "value", "path"))
        if not valid_cookie(domain, name, value, path) or item.get("partitionKey"):
            continue
        expires = item.get("expires", -1)
        if not isinstance(expires, (int, float)) or not math.isfinite(expires):
            continue
        rest = {"HttpOnly": None} if item.get("httpOnly") else {}
        if item.get("sameSite") in {"Strict", "Lax", "None"}:
            rest["SameSite"] = item["sameSite"]
        session.cookies.jar.set_cookie(Cookie(
            0, name, value, None, False, domain, True, domain.startswith("."),
            path, True, bool(item.get("secure")), int(expires) if expires > 0 else None,
            expires <= 0, None, None, rest, False,
        ))
        count += 1
    return count


class DiagnosticSession(base.ReadOnlySession):
    def __init__(self, inner, publish):
        self.publish = publish
        self.stage_override = None
        self.last_record = None
        super().__init__(inner, self._note)

    def _note(self, record):
        self.last_record = record
        if "error" in record:
            self.publish({"stage": self.stage_override or record["stage"], "error": "request_failed"})

    def _request(self, method, url, **kwargs):
        result = super()._request(method, url, **kwargs)
        self.publish(summarize(result, self.stage_override or self.last_record["stage"]))
        return result


def read_browser_sign(factory, session, user_agent, publish):
    state = {"blocked_requests": 0, "blocked_redirects": 0, "guard_failed": False}
    with factory() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context(user_agent=user_agent, service_workers="block")
            page = context.new_page()
            install_browser_guard(context, page, state)
            context.add_cookies(browser_cookies(session))
            response = page.goto(SIGN_URL, wait_until="networkidle", timeout=30000)
            current = SimpleNamespace(text=page.content(), status_code=response.status if response else 0,
                                      url=page.url, headers=response.headers if response else {})
            metadata = summarize(current, "browser_sign_page")
            publish(metadata)
            cookies = context.cookies()
            return metadata, cookies
        finally:
            publish({"stage": "browser_guards", "blocked_requests": state["blocked_requests"],
                     "blocked_redirects": state["blocked_redirects"], "guard_failed": state["guard_failed"],
                     "transport": "chromium", "service_workers_blocked": True})
            browser.close()


class HomepageBrowserChallengeStopped(RuntimeError):
    pass


def run_authenticated(username, password, publish, yamibo_module=None):
    if yamibo_module is None:
        sys.path.insert(0, str(ROOT))
        from checkin import yamibo as yamibo_module
    y = yamibo_module
    names = ("SESSION", "USERNAME", "PASSWORD", "sync_playwright", "check_in", "query_stats", "msg")
    missing = object()
    original = {name: getattr(y, name, missing) for name in names}
    records = []
    def record(event):
        records.append(event)
        publish(event)
    def forbidden(*args, **kwargs):
        raise base.UnsafeProbeRequest("Forbidden diagnostic action")
    def stop_legacy_browser(*args, **kwargs):
        raise HomepageBrowserChallengeStopped()
    try:
        y.SESSION = DiagnosticSession(original["SESSION"], record)
        y.USERNAME, y.PASSWORD = username, password
        y.check_in = y.query_stats = forbidden
        y.msg = []
        if original["sync_playwright"] is not missing:
            y.sync_playwright = stop_legacy_browser
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            success = y.login()
            record({"stage": "original_login_result", "reported_success": bool(success)})
            if not success:
                return 1
            y.SESSION.stage_override = "post_login_forum"
            y.SESSION.get(base.ORIGIN + "/forum.php", headers=y.HEADERS, impersonate="chrome")
            y.SESSION.stage_override = None
            sign_hash, signed, _ = y.get_sign_page()
            record({"stage": "original_sign_parser", "hash_present": sign_hash is not None,
                    "already_signed": signed, "sign_submission_attempted": False})
            sign_records = [item for item in records if item.get("stage") == "sign_page"]
            initial = sign_records[-1] if sign_records else {}
            if initial.get("authenticated_sign_page_readable"):
                record({"stage": "verification", "authenticated_sign_page_readable": True,
                        "sign_submission_attempted": False})
                return 0
            needs_browser = (initial.get("status") == 403 or initial.get("classification") == "challenge"
                             or initial.get("access_denied_marker") or initial.get("verification_marker"))
            if not needs_browser or original["sync_playwright"] is missing:
                record({"stage": "verification", "authenticated_sign_page_readable": False,
                        "sign_submission_attempted": False})
                return 1
            browser_result, cookies = read_browser_sign(
                original["sync_playwright"], original["SESSION"], y.HEADERS["user-agent"], record)
            count = copy_browser_cookies(original["SESSION"], cookies)
            cookies.clear()
            record({"stage": "cookie_transfer", "accepted_cookie_count": count})
            y.SESSION.stage_override = "cffi_sign_page_after_browser"
            y.SESSION.get(SIGN_URL, headers=y.HEADERS, impersonate="chrome")
            final = next(item for item in reversed(records) if item.get("stage") == "cffi_sign_page_after_browser")
            readable = final.get("authenticated_sign_page_readable", False)
            record({"stage": "comparison", "browser_readable": browser_result["authenticated_sign_page_readable"],
                    "cffi_after_cookie_copy_readable": readable, "sign_submission_attempted": False})
            return 0 if readable else 1
    except HomepageBrowserChallengeStopped:
        record({"stage": "homepage_challenge", "error": "homepage_browser_challenge_stopped",
                "sign_submission_attempted": False})
        return 1
    except Exception:
        record({"stage": "probe_result", "error": "probe_failed_no_raw_exception_logged",
                "sign_submission_attempted": False})
        return 1
    finally:
        for name, value in original.items():
            if value is missing:
                if hasattr(y, name):
                    delattr(y, name)
            else:
                setattr(y, name, value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-env", action="store_true")
    args = parser.parse_args()
    visible = sys.stdout
    def emit(event):
        print(json.dumps(event, ensure_ascii=False), file=visible, flush=True)
    if args.from_env:
        username, password = os.environ.get("YAMIBO_USERNAME"), os.environ.get("YAMIBO_PASSWORD")
        if not username or not password:
            emit({"stage": "setup", "error": "credentials_not_configured"})
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
