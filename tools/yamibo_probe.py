"""Read-only Yamibo probe. Credentials are entered privately, never saved.

Run from the repository: uv run --frozen --python 3.13 python tools/yamibo_probe.py
Use --anonymous to inspect public pages without credentials. No sign-in reward
request, account statistics request or notification is permitted by this probe.
"""

import argparse
import contextlib
import getpass
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import parse_qsl, urlsplit, urlencode


ORIGIN = "https://bbs.yamibo.com"
KNOWN_PATHS = {"/forum.php", "/member.php", "/plugin.php"}
KNOWN_TITLES = re.compile(
    r"^(?:\d{4}年\d{1,2}月\d{1,2}日 - |登录 - )?百合会(?: - Powered by Discuz!)?$"
)


class PageMarkers(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.login_link = False
        self.logout_link = False
        self.buttons = []
        self.active_button = None
        self.in_title = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag != "a":
            return
        href = attrs.get("href", "")
        parts = urlsplit(href)
        query = dict(parse_qsl(parts.query))
        if parts.path.endswith("member.php") and query.get("mod") == "logging":
            self.login_link |= query.get("action") == "login"
            self.logout_link |= query.get("action") == "logout"
        if "btna" in attrs.get("class", "").split():
            self.active_button = {"text": "", "has_hash": bool(
                parts.path.endswith("plugin.php") and query.get("id") == "zqlj_sign"
                and re.fullmatch(r"[a-f0-9]+", query.get("sign", ""))
            )}

    def handle_data(self, data):
        if self.in_title:
            self.title += data
        if self.active_button is not None:
            self.active_button["text"] += data

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag == "a" and self.active_button is not None:
            self.buttons.append(self.active_button)
            self.active_button = None


def safe_url(url):
    try:
        parts = urlsplit(str(url))
        if parts.scheme != "https" or parts.hostname != "bbs.yamibo.com":
            return "[other-origin]"
        if parts.path not in KNOWN_PATHS:
            return ORIGIN + "/[other-path]"
        allowed = {"id": {"zqlj_sign"}, "mod": {"logging"}, "action": {"login", "logout"}}
        safe_query = [(key, value) for key, value in parse_qsl(parts.query)
                      if value in allowed.get(key, set())]
        return ORIGIN + parts.path + ("?" + urlencode(safe_query) if safe_query else "")
    except (ValueError, TypeError):
        return "[invalid-url]"


def summarize(response, stage):
    body = response.text
    markers = PageMarkers()
    markers.feed(body)
    title = " ".join(markers.title.split())
    title_allowed = bool(KNOWN_TITLES.fullmatch(title))
    challenge = bool(re.search(r"nox_jst_v1|百度云加速|安全验证|人机验证|js_challenge", body, re.I)) or (response.status_code in {403, 405, 429} and "nox" in body.lower())
    authentication = ("authenticated" if markers.logout_link else
                      "guest" if markers.login_link or "需要先登录" in body else "unknown")
    ready = any("点击打卡" in b["text"] and b["has_hash"] for b in markers.buttons)
    signed = any("今日已打卡" in b["text"] and "点击打卡" not in b["text"] for b in markers.buttons)
    if challenge:
        classification = "challenge"
    elif not 200 <= response.status_code < 300:
        classification = "http_error"
    elif authentication == "guest":
        classification = "guest"
    elif authentication == "authenticated" and signed:
        classification = "already_signed"
    elif authentication == "authenticated" and ready:
        classification = "ready"
    else:
        classification = "unknown"
    mime = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if mime not in {"text/html", "text/xml", "application/xml", "application/json", "text/plain"}:
        mime = "other"
    return {
        "stage": stage,
        "status": response.status_code,
        "url": safe_url(response.url),
        "title": title if title_allowed else "[omitted]",
        "title_omitted": not title_allowed,
        "content_type": mime,
        "body_length": len(body),
        "authentication": authentication,
        "classification": classification,
        "challenge_marker": challenge,
        "legacy_button_match": bool(re.search(r'class="btna"[^>]*>([^<]+)<', body)),
        "own_button_present": bool(markers.buttons),
        "sign_link_present": ready,
        "my_sign_marker": "我的打卡动态" in body,
    }


class UnsafeProbeRequest(RuntimeError):
    pass


class BrowserChallengeRequiresSeparateInspection(RuntimeError):
    """The read-only probe cannot launch the legacy unrestricted browser."""


def _stop_browser_challenge(*args, **kwargs):
    raise BrowserChallengeRequiresSeparateInspection()


class ReadOnlySession:
    def __init__(self, inner, emit):
        self.inner = inner
        self.emit = emit

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def _request(self, method, url, **kwargs):
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query))
        query.update(kwargs.get("params") or {})
        if (parts.scheme != "https" or parts.hostname != "bbs.yamibo.com"
                or parts.username or parts.password or parts.fragment or parts.port not in (None, 443)):
            raise UnsafeProbeRequest("Unexpected origin")
        if parts.path == "/forum.php" and method == "GET" and not query:
            stage = "forum"
        elif (parts.path == "/member.php" and query.get("mod") == "logging"
              and query.get("action") == "login"
              and set(query) <= {"mod", "action", "infloat", "frommessage", "inajax", "ajaxtarget", "loginhash", "loginsubmit"}):
            stage = "login_submit" if method == "POST" else "login_form"
        elif (parts.path == "/plugin.php" and method == "GET"
              and query == {"id": "zqlj_sign"}):
            stage = "sign_page"
        else:
            raise UnsafeProbeRequest("Request outside read-only probe")
        kwargs.setdefault("timeout", 20)
        # Do not follow a redirect to an unreviewed endpoint or replay a login POST.
        kwargs["allow_redirects"] = False
        try:
            result = getattr(self.inner, method.lower())(url, **kwargs)
        except Exception:
            self.emit({"stage": stage, "error": "request_failed"})
            raise
        self.emit(summarize(result, stage))
        return result

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, **kwargs)


def run_probe(args, emit):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from checkin import yamibo

    observations = []
    publish = emit
    def record(value):
        observations.append(value)
        publish(value)
    emit = record
    missing = object()
    original = {name: getattr(yamibo, name, missing) for name in
                ("SESSION", "USERNAME", "PASSWORD", "sync_playwright")}
    try:
        yamibo.SESSION = ReadOnlySession(original["SESSION"], emit)
        if original["sync_playwright"] is not missing:
            yamibo.sync_playwright = _stop_browser_challenge
        # Never publish the original script's raw error excerpts or browser logs.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            if args.anonymous:
                yamibo.SESSION.get(ORIGIN + "/forum.php", headers=yamibo.HEADERS, impersonate="chrome")
                yamibo.SESSION.get(ORIGIN + "/plugin.php?id=zqlj_sign", headers=yamibo.HEADERS, impersonate="chrome")
                return 0
            if args.from_env:
                username = os.environ.get("YAMIBO_USERNAME")
                password = os.environ.get("YAMIBO_PASSWORD")
                if not username or not password:
                    emit({"stage": "setup", "error": "credentials_not_configured"})
                    return 2
            else:
                username = getpass.getpass("百合会用户名（输入不显示）: ")
                password = getpass.getpass("百合会密码（输入不显示）: ")
            yamibo.USERNAME, yamibo.PASSWORD = username, password
            login_reported_success = yamibo.login()
            emit({"stage": "login_result", "original_login_reported_success": login_reported_success})
            if not login_reported_success:
                return 1
            sign_hash, signed, _ = yamibo.get_sign_page()
            recognized = signed is True or (signed is False and sign_hash is not None)
            emit({"stage": "probe_result", "original_parser_recognized_page": recognized,
                  "sign_submission_attempted": False})
            sign_records = [r for r in observations if r.get("stage") == "sign_page"]
            verified = bool(sign_records and sign_records[-1].get("classification") in {"ready", "already_signed"})
            emit({"stage": "verification", "authenticated_page_verified": verified})
            return 0 if recognized and verified else 1
    except BrowserChallengeRequiresSeparateInspection:
        emit({"stage": "probe_result", "error": "browser_challenge_requires_separate_inspection"})
        return 1
    except UnsafeProbeRequest:
        emit({"stage": "probe_result", "error": "unexpected_request_blocked"})
        return 1
    except Exception:
        emit({"stage": "probe_result", "error": "probe_failed_no_raw_exception_logged"})
        return 1
    finally:
        for name, value in original.items():
            if value is missing:
                if hasattr(yamibo, name):
                    delattr(yamibo, name)
            else:
                setattr(yamibo, name, value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--anonymous", action="store_true")
    mode.add_argument("--from-env", action="store_true")
    parser.add_argument("--output", type=Path, help="New metadata-only JSONL file; existing files are never overwritten")
    args = parser.parse_args()
    try:
        output = args.output.open("x", encoding="utf-8") if args.output else None
    except OSError:
        print("诊断输出文件无法创建（不会覆盖已有文件）。", file=sys.stderr)
        return 2
    visible_stdout = sys.stdout
    try:
        def emit(record):
            line = json.dumps(record, ensure_ascii=False)
            print(line, file=visible_stdout, flush=True)
            if output:
                output.write(line + "\n")
                output.flush()
        return run_probe(args, emit)
    finally:
        if output:
            output.close()


if __name__ == "__main__":
    raise SystemExit(main())
