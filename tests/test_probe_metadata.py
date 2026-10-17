import importlib.util
import json
import os
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from types import SimpleNamespace
import unittest


ROOT = next(candidate for parent in Path(__file__).resolve().parents
            for candidate in (parent, parent / "Daily-Bonus")
            if (candidate / "checkin/yamibo.py").is_file())
MODULE = Path(os.environ.get("YAMIBO_PROBE_SOURCE", "tools/yamibo_probe.py"))
if not MODULE.is_absolute():
    MODULE = ROOT / MODULE
spec = importlib.util.spec_from_file_location("diagnose_yamibo", MODULE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def response(body, status=200, url="https://bbs.yamibo.com/plugin.php?id=zqlj_sign"):
    return SimpleNamespace(text=body, status_code=status, url=url,
                           headers={"content-type": "text/html; charset=utf-8"})


class MetadataTests(unittest.TestCase):
    def test_guest_page_with_other_users_signed_is_guest(self):
        body = '<a href="member.php?mod=logging&action=login">登录</a><td>今日已打卡</td><a class="btna" href="plugin.php?id=zqlj_sign&sign=abc123">点击打卡</a>'
        result = probe.summarize(response(body), "sign_page")
        self.assertEqual(result["classification"], "guest")
        self.assertEqual(result["authentication"], "guest")

    def test_http_200_challenge_is_not_ready(self):
        result = probe.summarize(response('<script>nox_jst_v1</script>'), "sign_page")
        self.assertEqual(result["classification"], "challenge")

    def test_authenticated_ready_page(self):
        body = '<a href="member.php?mod=logging&action=logout">退出</a><a class="extra btna" href="plugin.php?id=zqlj_sign&sign=abcdef12"><span>点击打卡</span></a>'
        result = probe.summarize(response(body), "sign_page")
        self.assertEqual(result["classification"], "ready")
        self.assertFalse(result["legacy_button_match"])

    def test_signed_requires_own_button(self):
        body = '<a href="member.php?mod=logging&action=logout">退出</a><a class="btna">今日已打卡</a>'
        self.assertEqual(probe.summarize(response(body), "sign_page")["classification"], "already_signed")
        body = '<a href="member.php?mod=logging&action=logout">退出</a><td>今日已打卡</td>'
        self.assertEqual(probe.summarize(response(body), "sign_page")["classification"], "unknown")

    def test_does_not_publish_arbitrary_titles_urls_or_content(self):
        injected = "FAKE_SENSITIVE_VALUE_12489"
        r = response(f'<title>{injected}</title><p>{injected}</p>',
                     url=f'https://user:{injected}@bbs.yamibo.com/plugin.php?id=zqlj_sign&sign={injected}#{injected}')
        output = json.dumps(probe.summarize(r, "sign_page"))
        self.assertNotIn(injected, output)
        self.assertNotIn("user:", output)
        self.assertIn("title_omitted", output)

    def test_only_known_forum_title_is_logged(self):
        r = response('<title>2026年10月17日 - 百合会 - Powered by Discuz!</title>')
        self.assertEqual(probe.summarize(r, "sign_page")["title"],
                         '2026年10月17日 - 百合会 - Powered by Discuz!')

    def test_unknown_origin_and_path_are_not_disclosed(self):
        for url in ("https://unknown.invalid/personal-data", "https://bbs.yamibo.com/personal-data"):
            output = json.dumps(probe.summarize(response("", url=url), "sign_page"))
            self.assertNotIn("personal-data", output)
            self.assertNotIn("unknown.invalid", output)


class FakeSession:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return response("", url=url)

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return response("", url=url)


class ReadOnlyTests(unittest.TestCase):
    def setUp(self):
        self.inner = FakeSession()
        self.records = []
        self.session = probe.ReadOnlySession(self.inner, self.records.append)

    def test_never_submits_sign_including_params(self):
        for kwargs in ({"url":"https://bbs.yamibo.com/plugin.php?id=zqlj_sign&sign=abcdef"},
                       {"url":"https://bbs.yamibo.com/plugin.php", "params":{"id":"zqlj_sign", "sign":"abcdef"}}):
            with self.assertRaises(probe.UnsafeProbeRequest):
                self.session.get(**kwargs)
        self.assertEqual(self.inner.calls, [])

    def test_does_not_query_credits_or_send_notifications(self):
        for url in ("https://bbs.yamibo.com/home.php?mod=spacecp&ac=credit",
                    "https://api.telegram.org/"):
            with self.assertRaises(probe.UnsafeProbeRequest):
                self.session.get(url)
        self.assertEqual(self.inner.calls, [])

    def test_allows_only_expected_login_post(self):
        self.session.post("https://bbs.yamibo.com/member.php", params={"mod":"logging", "action":"login"}, data={"username":"FAKE_USER", "password":"FAKE_PASSWORD"})
        self.assertEqual(len(self.inner.calls), 1)
        output = json.dumps(self.records)
        self.assertNotIn("FAKE_USER", output)
        self.assertNotIn("FAKE_PASSWORD", output)
        self.assertEqual(self.records[0]["stage"], "login_submit")

    def test_allowed_read_emits_metadata_and_sets_timeout(self):
        self.session.get("https://bbs.yamibo.com/plugin.php?id=zqlj_sign")
        self.assertEqual(self.records[0]["stage"], "sign_page")
        self.assertEqual(self.inner.calls[0][2]["timeout"], 20)


if __name__ == "__main__":
    unittest.main()
