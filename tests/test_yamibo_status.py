import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
sys.dont_write_bytecode = True
import types
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

ROOT = Path(os.environ.get("YAMIBO_STATUS_SOURCE_ROOT", Path(__file__).resolve().parents[1]))

from curl_cffi.requests.exceptions import RequestException as NetworkError


def load_modules():
    modules = {}
    package = types.ModuleType("checkin")
    package.__path__ = [str(ROOT / "checkin")]
    modules["checkin"] = package
    net = types.ModuleType("checkin.net")
    net.open_route = Mock(return_value=True)
    modules["checkin.net"] = net
    package.net = net
    for name in ("bilibili", "netease", "pica", "uma", "v2ex", "yurifans"):
        module = types.ModuleType("checkin." + name)
        module.main = Mock(return_value="other service result")
        setattr(package, name, module)
        modules["checkin." + name] = module
    with patch.dict(sys.modules, modules), patch.object(os, "environ", {}):
        def load(name, path):
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return module
        yamibo = load("checkin.yamibo", ROOT / "checkin/yamibo.py")
        package.yamibo = yamibo
        message = load("status_candidate_message", ROOT / "message.py")
    return yamibo, message


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.y, self.m = load_modules()
        self.y.USERNAME = "fake-user"
        self.y.PASSWORD = "fake-password"
        self.y.msg = []
        self.y.SESSION = Mock()
        self.y.SESSION.get.return_value.status_code = 200
        self.y.SESSION.get.return_value.headers = {}
        self.y.SESSION.post.return_value.status_code = 200
        self.y.SESSION.post.return_value.headers = {}
        self.y.login = Mock(return_value=True)
        self.y.get_sign_page = Mock(return_value=("abcdef", False, "page"))
        self.real_check_in = self.y.check_in
        self.y.check_in = Mock(return_value=(True, "signed"))
        self.y.query_stats = Mock()
        self.y.SESSION.get.return_value.text = "fresh page"
        self.m.time.sleep = Mock()

    def failure(self, action, retryable=False):
        with self.assertRaises(Exception) as captured:
            action()
        error = captured.exception
        self.assertEqual(type(error).__name__, "YamiboError")
        self.assertEqual(error.retryable, retryable)
        self.assertNotIn("FAKE_SENSITIVE", str(error))
        return error

    def runner(self):
        self.assertTrue(callable(getattr(self.m, "run_yamibo", None)),
                        "Yamibo needs a runner with explicit outcome")
        return self.m.run_yamibo

    def error(self, retryable):
        self.assertTrue(hasattr(self.y, "YamiboError"), "Missing safe Yamibo failure type")
        return self.y.YamiboError("阶段失败", retryable=retryable)

    def test_login_false_is_failure(self):
        self.y.login.return_value = False
        self.failure(self.y.main)
        self.y.check_in.assert_not_called()

    def test_invalid_sign_page_is_failure(self):
        self.y.get_sign_page.return_value = (None, None, None)
        self.failure(self.y.main)
        self.y.check_in.assert_not_called()

    def test_missing_hash_is_not_already_signed(self):
        self.y.get_sign_page.return_value = (None, False, "我的打卡动态")
        self.failure(self.y.main)
        self.y.check_in.assert_not_called()

    def test_checkin_false_is_failure(self):
        self.y.check_in.return_value = (False, "failed")
        self.failure(self.y.main)
        self.y.query_stats.assert_not_called()

    def test_already_signed_needs_no_hash(self):
        self.y.get_sign_page.return_value = (None, True, "signed")
        self.assertIn("今日已签到", self.y.main())
        self.y.check_in.assert_not_called()

    def test_messages_clear_between_attempts(self):
        self.y.msg.append({"name": "stale", "value": "old failure"})
        self.y.get_sign_page.return_value = (None, True, "signed")
        self.assertNotIn("old failure", self.y.main())

    def test_missing_credentials_is_failure(self):
        self.y.USERNAME = None
        self.failure(self.y.main)
        self.y.login.assert_not_called()

    def test_network_before_submission_is_retryable(self):
        self.y.login.side_effect = NetworkError("FAKE_SENSITIVE")
        self.failure(self.y.main, retryable=True)

    def test_checkin_network_failure_is_not_replayed(self):
        # Use the real check_in so its mutation boundary is exercised.
        self.y.check_in = self.real_check_in
        self.y.SESSION.get.side_effect = NetworkError("FAKE_SENSITIVE")
        self.failure(self.y.main, retryable=False)

    def successful_main(self):
        try:
            return self.y.main()
        except Exception as error:
            self.fail("Confirmed success must survive supplementary query errors: " + type(error).__name__)

    def test_stats_exception_after_success_is_warning(self):
        self.y.query_stats.side_effect = RuntimeError("FAKE_SENSITIVE")
        result = self.successful_main()
        self.assertIn("查询", result)
        self.assertNotIn("FAKE_SENSITIVE", result)
        self.y.check_in.assert_called_once()

    def test_refresh_exception_after_success_does_not_retry(self):
        self.y.SESSION.get.side_effect = NetworkError("FAKE_SENSITIVE")
        result = self.successful_main()
        self.assertNotIn("FAKE_SENSITIVE", result)
        self.y.check_in.assert_called_once()

    def test_runner_retries_only_retryable_failure(self):
        runner = self.runner()
        action = Mock(side_effect=[self.error(True), "ok"])
        self.assertEqual(runner(action, delay=0), ("ok", True))
        self.assertEqual(action.call_count, 2)

    def test_runner_stops_permanent_failure(self):
        runner = self.runner()
        action = Mock(side_effect=self.error(False))
        text, success = runner(action, delay=0)
        self.assertFalse(success)
        self.assertEqual(action.call_count, 1)
        self.assertTrue(text)

    def test_runner_exhaustion_is_failure(self):
        runner = self.runner()
        action = Mock(side_effect=self.error(True))
        _, success = runner(action, attempts=3, delay=0)
        self.assertFalse(success)
        self.assertEqual(action.call_count, 3)

    def test_runner_network_before_submission_retries(self):
        runner = self.runner()
        self.y.sign_submission_started = False
        action = Mock(side_effect=[NetworkError("FAKE_SENSITIVE"), "ok"])
        self.assertEqual(runner(action, delay=0), ("ok", True))
        self.assertEqual(action.call_count, 2)

    def test_runner_network_after_submission_does_not_retry(self):
        runner = self.runner()
        self.y.sign_submission_started = True
        action = Mock(side_effect=NetworkError("FAKE_SENSITIVE"))
        text, success = runner(action, delay=0)
        self.assertFalse(success)
        self.assertEqual(action.call_count, 1)
        self.assertNotIn("FAKE_SENSITIVE", text)

    def test_retryable_error_cannot_override_submission_boundary(self):
        runner = self.runner()
        self.y.sign_submission_started = True
        action = Mock(side_effect=self.error(True))
        _, success = runner(action, delay=0)
        self.assertFalse(success)
        self.assertEqual(action.call_count, 1)

    def test_runner_unexpected_error_is_safe_and_terminal(self):
        runner = self.runner()
        action = Mock(side_effect=ValueError("FAKE_SENSITIVE"))
        text, success = runner(action, delay=0)
        self.assertFalse(success)
        self.assertEqual(action.call_count, 1)
        self.assertNotIn("FAKE_SENSITIVE", text)

    def entry(self, success, telegram=True):
        self.assertTrue(callable(getattr(self.m, "main", None)),
                        "message.main must return process exit status")
        self.m.run_yamibo = Mock(return_value=("safe result", success))
        self.m.send_message = Mock(return_value=True)
        self.m.TG_BOT_TOKEN = "fake-telegram" if telegram else None
        with patch.object(os, "environ", {"YAMIBO_USERNAME": "fake", "YAMIBO_PASSWORD": "fake"}), contextlib.redirect_stdout(io.StringIO()):
            code = self.m.main()
        return code

    def test_failed_yamibo_sends_notification_and_exits_nonzero(self):
        self.assertEqual(self.entry(False), 1)
        self.m.send_message.assert_called_once()

    def test_failed_yamibo_without_notification_exits_nonzero(self):
        self.assertEqual(self.entry(False, telegram=False), 1)
        self.m.send_message.assert_not_called()

    def test_successful_yamibo_exits_zero(self):
        self.assertEqual(self.entry(True), 0)

    def test_other_service_runner_unchanged(self):
        action = Mock(side_effect=[ValueError("old"), "legacy result"])
        self.assertEqual(self.m.run_module(action, delay=0), "legacy result")
        self.assertEqual(action.call_count, 2)

    def test_login_fallback_does_not_expose_response(self):
        real = load_modules()[0]
        real.solve_waf = Mock(return_value=True)
        real.SESSION = Mock()
        real.SESSION.get.return_value.status_code = 200
        real.SESSION.get.return_value.headers = {}
        real.SESSION.post.return_value.status_code = 200
        real.SESSION.post.return_value.headers = {}
        real.SESSION.get.return_value.text = '<input name="formhash" value="abcdef">'
        real.SESSION.post.return_value.text = "FAKE_SENSITIVE"
        self.assertFalse(real.login())
        self.assertNotIn("FAKE_SENSITIVE", str(real.msg))

    def test_route_preflight_failure_is_retryable(self):
        real = load_modules()[0]
        real.net.open_route.return_value = False
        self.failure(real.login, retryable=True)

    def test_login_failure_paragraph_does_not_expose_response(self):
        real = load_modules()[0]
        real.solve_waf = Mock(return_value=True)
        real.SESSION = Mock()
        real.SESSION.get.return_value.status_code = 200
        real.SESSION.get.return_value.headers = {}
        real.SESSION.post.return_value.status_code = 200
        real.SESSION.post.return_value.headers = {}
        real.SESSION.get.return_value.text = '<input name="formhash" value="abcdef">'
        real.SESSION.post.return_value.text = "登录失败<p>FAKE_SENSITIVE</p>"
        self.assertFalse(real.login())
        self.assertNotIn("FAKE_SENSITIVE", str(real.msg))

    def test_real_main_retry_before_submission_signs_once(self):
        runner = self.runner()
        self.y.login.side_effect = [NetworkError("FAKE_SENSITIVE"), True]
        text, success = runner(self.y.main, delay=0)
        self.assertTrue(success)
        self.assertEqual(self.y.login.call_count, 2)
        self.y.check_in.assert_called_once()
        self.assertNotIn("FAKE_SENSITIVE", text)

    def test_real_main_uncertain_submission_runs_once(self):
        runner = self.runner()
        self.y.check_in = self.real_check_in
        self.y.SESSION.get.side_effect = NetworkError("FAKE_SENSITIVE")
        text, success = runner(self.y.main, delay=0)
        self.assertFalse(success)
        self.y.login.assert_called_once()
        self.y.SESSION.get.assert_called_once()
        self.assertTrue(self.y.sign_submission_started)
        self.assertNotIn("FAKE_SENSITIVE", text)

    def test_notification_failure_exits_nonzero(self):
        self.assertTrue(callable(getattr(self.m, "main", None)))
        self.m.run_yamibo = Mock(return_value=("ok", True))
        self.m.send_message = Mock(return_value=False)
        self.m.TG_BOT_TOKEN = "fake"
        with patch.object(os, "environ", {"YAMIBO_USERNAME": "fake", "YAMIBO_PASSWORD": "fake"}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.m.main(), 1)

    def test_other_services_keep_using_legacy_runner(self):
        self.assertTrue(callable(getattr(self.m, "main", None)))
        self.m.run_module = Mock(return_value="legacy")
        self.m.run_yamibo = Mock(return_value=("yamibo", False))
        self.m.TG_BOT_TOKEN = None
        settings = {key: "fake" for key in (
            "YAMIBO_USERNAME", "YAMIBO_PASSWORD", "UMA_COOKIES", "YURIFANS_EMAIL",
            "YURIFANS_PASSWORD", "V2EX_COOKIES", "BILIBILI_COOKIES", "PICA_USERNAME",
            "PICA_PASSWORD", "NETEASE_MUSIC_COOKIES")}
        with patch.object(os, "environ", settings), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.m.main(), 1)
        self.assertEqual(self.m.run_module.call_count, 6)
        self.m.run_yamibo.assert_called_once_with(self.y.main)



class ResponseClassificationTests(unittest.TestCase):
    def setUp(self):
        self.y, self.m = load_modules()
        self.y.USERNAME, self.y.PASSWORD = "FAKE_USER", "FAKE_PASSWORD"
        self.y.SESSION = Mock()
        self.y.msg = []
        self.m.time.sleep = Mock()

    def response(self, body, status=200, headers=None, url=None):
        return SimpleNamespace(text=body, status_code=status, headers=headers or {},
            url=url or "https://bbs.yamibo.com/plugin.php?id=zqlj_sign")

    def assert_page_failure(self, response, expected):
        self.y.SESSION.get.return_value = response
        try:
            self.y.get_sign_page()
        except self.y.YamiboError as error:
            self.assertIn(expected, str(error))
            self.assertFalse(error.retryable)
            self.assertNotIn("FAKE_SENSITIVE", str(error))
        else:
            self.fail("Invalid response must raise a specific safe failure")

    def test_403_cloudflare_is_specific_failure_even_with_fake_signed_button(self):
        body = '<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/a.js"></script><a class="btna">今日已打卡</a>FAKE_SENSITIVE'
        self.assert_page_failure(self.response(body,403), "Cloudflare")

    def test_200_cloudflare_challenge_is_not_a_sign_page(self):
        body = '<title>Just a moment...</title><script>cf-chl-widget</script>FAKE_SENSITIVE'
        self.assert_page_failure(self.response(body), "Cloudflare")

    def test_cf_mitigated_header_is_definitive_with_no_body_marker(self):
        self.assert_page_failure(self.response("FAKE_SENSITIVE",200,{"CF-Mitigated":"challenge"}), "Cloudflare")

    def test_plain_403_is_http_failure_not_cloudflare_guess(self):
        response = self.response('<a class="btna">今日已打卡</a>FAKE_SENSITIVE',403,{"server":"cloudflare"})
        self.assert_page_failure(response, "HTTP 403")

    def test_non_2xx_error_cannot_be_accepted_by_button_or_hash(self):
        for status in (302,404,500):
            with self.subTest(status=status):
                body = '<a class="btna" href="?sign=abcdef">今日已打卡</a>我的打卡动态FAKE_SENSITIVE'
                self.assert_page_failure(self.response(body,status), "HTTP " + str(status))

    def test_login_page_redirect_is_expired_authentication(self):
        body = '<form id="loginform_test"><input name="username"></form><a class="btna">今日已打卡</a>'
        self.assert_page_failure(self.response(body,url="https://bbs.yamibo.com/member.php?mod=logging&action=login"), "登录")

    def test_login_prompt_is_expired_authentication(self):
        self.assert_page_failure(self.response('需要先登录<a class="btna">今日已打卡</a>'), "登录")

    def test_guest_login_form_with_fake_button_is_expired_authentication(self):
        body = '<form name="login" id="loginform_x"><input name="username"></form><a class="btna">今日已打卡</a>'
        self.assert_page_failure(self.response(body), "登录")

    def test_normal_unsigned_page_keeps_original_regex(self):
        body = '我的打卡动态<a class="btna" href="plugin.php?id=zqlj_sign&sign=abcdef12">点击打卡</a>'
        self.y.SESSION.get.return_value=self.response(body)
        self.assertEqual(self.y.get_sign_page(),("abcdef12",False,body))

    def test_normal_signed_page_keeps_original_regex_and_needs_no_hash(self):
        body = '我的打卡动态<a class="btna">今日已打卡</a>'
        self.y.SESSION.get.return_value=self.response(body)
        self.assertEqual(self.y.get_sign_page(),(None,True,body))

    def test_cloudflare_failure_reaches_message_runner_without_retry_or_submission(self):
        self.y.login = Mock(return_value=True)
        self.y.check_in, self.y.query_stats = Mock(), Mock()
        self.y.SESSION.get.return_value=self.response('<title>Just a moment...</title><script>cf-chl-x</script>',403)
        text,success=self.m.run_yamibo(self.y.main,delay=0)
        self.assertFalse(success)
        self.assertIn("Cloudflare",text)
        self.y.login.assert_called_once()
        self.y.check_in.assert_not_called()
        self.y.query_stats.assert_not_called()

    def test_challenge_after_submission_is_failure_without_replay(self):
        self.y.login = Mock(return_value=True)
        self.y.get_sign_page = Mock(return_value=("abcdef",False,"page"))
        self.y.query_stats=Mock()
        self.y.SESSION.get.return_value=self.response('<title>Just a moment...</title><script>cf-chl-x</script>',403)
        text,success=self.m.run_yamibo(self.y.main,delay=0)
        self.assertFalse(success)
        self.assertIn("Cloudflare",text)
        self.assertTrue(self.y.sign_submission_started)
        self.y.login.assert_called_once()
        self.y.SESSION.get.assert_called_once()
        self.y.query_stats.assert_not_called()

if __name__ == "__main__":
    unittest.main(verbosity=2)
