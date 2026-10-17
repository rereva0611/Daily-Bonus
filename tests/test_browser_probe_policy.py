import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("browser_probe", ROOT / "tools/yamibo_browser_probe.py")
module = importlib.util.module_from_spec(spec)
with patch.object(os, "environ", {}):
    spec.loader.exec_module(module)


class BrowserPolicyTests(unittest.TestCase):
    def test_only_guest_document_and_same_origin_assets_allowed(self):
        cases = [
            ("GET", "https://bbs.yamibo.com/forum.php", "document", True),
            ("GET", "https://bbs.yamibo.com/", "document", True),
            ("GET", "https://bbs.yamibo.com/_nox/a.js", "script", True),
            ("GET", "https://bbs.yamibo.com/plugin.php?id=zqlj_sign&sign=abc", "document", False),
            ("GET", "https://bbs.yamibo.com/plugin.php?id=zqlj_sign&sign=abc", "script", False),
            ("GET", "https://bbs.yamibo.com/member.php?mod=logging&action=logout", "document", False),
            ("POST", "https://bbs.yamibo.com/member.php", "document", False),
            ("GET", "https://unknown.invalid/a.js", "script", False),
            ("GET", "https://bbs.yamibo.com/home.php?mod=spacecp&ac=credit", "script", False),
            ("GET", "https://bbs.yamibo.com/forum.php", "fetch", False),
        ]
        for method, url, kind, expected in cases:
            with self.subTest(method=method, url=url, kind=kind):
                self.assertEqual(module.allowed_browser_request(method, url, kind), expected)


class FakeSession:
    def __init__(self, body):
        self.body = body
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        return SimpleNamespace(text=self.body, status_code=200, url=url, headers={})


class AuthenticatedProbeTests(unittest.TestCase):
    def execute(self, body, login=True, error=None):
        session = FakeSession(body)
        records = []
        def sign_page():
            if error:
                raise error
            module.yamibo.SESSION.get("https://bbs.yamibo.com/plugin.php?id=zqlj_sign")
            return "abcdef12", False, body
        with patch.object(module.yamibo, "SESSION", session), \
             patch.object(module.yamibo, "login", return_value=login), \
             patch.object(module.yamibo, "get_sign_page", side_effect=sign_page), \
             patch.object(module.yamibo, "check_in", Mock()) as check_in, \
             patch.object(module.yamibo, "query_stats", Mock()) as stats:
            originals = {name: getattr(module.yamibo, name) for name in
                         ("SESSION", "USERNAME", "PASSWORD", "sync_playwright", "check_in", "query_stats")}
            result = module.run_authenticated("FAKE_ACCOUNT", "FAKE_PASSWORD", records.append)
            for name, value in originals.items():
                self.assertIs(getattr(module.yamibo, name), value)
            check_in.assert_not_called()
            stats.assert_not_called()
        return result, records, session

    def test_ready_is_observed_without_checkin(self):
        body = '<a href="member.php?mod=logging&action=logout">退出</a><a class="btna" href="plugin.php?id=zqlj_sign&sign=abcdef12">点击打卡</a>'
        code, records, session = self.execute(body)
        self.assertEqual(code, 0)
        self.assertEqual(len(session.urls), 1)
        self.assertTrue(records[-1]["authenticated_page_verified"])
        self.assertNotIn("FAKE_PASSWORD", json.dumps(records))

    def test_guest_is_not_success_even_if_old_parser_accepts(self):
        body = '<a href="member.php?mod=logging&action=login">登录</a><a class="btna" href="plugin.php?id=zqlj_sign&sign=abcdef12">点击打卡</a>'
        code, records, _ = self.execute(body)
        self.assertEqual(code, 1)
        self.assertFalse(records[-1]["authenticated_page_verified"])

    def test_failed_login_does_not_request_sign_page(self):
        code, records, session = self.execute("", login=False)
        self.assertEqual(code, 1)
        self.assertEqual(session.urls, [])

    def test_failure_restores_state_and_omits_raw_exception(self):
        code, records, _ = self.execute("", error=RuntimeError("FAKE_SENSITIVE_VALUE"))
        self.assertEqual(code, 1)
        self.assertNotIn("FAKE_SENSITIVE_VALUE", json.dumps(records))


if __name__ == "__main__":
    unittest.main()
