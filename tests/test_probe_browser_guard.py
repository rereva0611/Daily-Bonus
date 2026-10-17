import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.dont_write_bytecode = True
def repository_root():
    configured = os.environ.get("YAMIBO_PROBE_REPO")
    if configured:
        return Path(configured).resolve()
    for parent in Path(__file__).resolve().parents:
        for candidate in (parent, parent / "Daily-Bonus"):
            if (candidate / "checkin/yamibo.py").is_file():
                return candidate
    raise RuntimeError("Set YAMIBO_PROBE_REPO to the repository root")


REPO = repository_root()
TARGET = Path(os.environ.get("YAMIBO_PROBE_SOURCE", str(REPO / "tools/yamibo_probe.py")))
if not TARGET.is_absolute():
    TARGET = REPO / TARGET
spec = importlib.util.spec_from_file_location("browser_guard_probe", TARGET)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def response():
    return SimpleNamespace(text='<script src="/_nox/challenge.js"></script>',
        status_code=405, url="https://bbs.yamibo.com/forum.php", headers={})


class BrowserGuardTests(unittest.TestCase):
    def fake_module(self, browser=True):
        module = ModuleType("checkin.yamibo")
        module.SESSION = Mock()
        module.SESSION.get.return_value = response()
        module.USERNAME = "FAKE_ORIGINAL_USER"
        module.PASSWORD = "FAKE_ORIGINAL_PASSWORD"
        module.BASE_URL = "https://bbs.yamibo.com"
        module.HEADERS = {}
        module.get_sign_page = Mock(return_value=(None, None, None))
        module.check_in = Mock(side_effect=AssertionError("Forbidden check-in"))
        module.query_stats = Mock(side_effect=AssertionError("Forbidden stats"))
        module.send_message = Mock(side_effect=AssertionError("Forbidden notification"))
        if browser:
            module.sync_playwright = MagicMock()
            playwright = module.sync_playwright.return_value.__enter__.return_value
            playwright.chromium.launch.return_value.new_context.return_value.cookies.return_value = []
            # Execute the existing solve_waf function itself, with only I/O replaced.
            tree = ast.parse((REPO / "checkin/yamibo.py").read_text())
            function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                            and node.name == "solve_waf")
            exec(compile(ast.Module(body=[function], type_ignores=[]),
                         str(REPO / "checkin/yamibo.py"), "exec"), module.__dict__)
            module.login = module.solve_waf
        else:
            module.login = Mock(return_value=False)
        return module

    def run_fake(self, module, *, anonymous=False):
        package = ModuleType("checkin")
        package.yamibo = module
        records = []
        output = io.StringIO()
        args = SimpleNamespace(anonymous=anonymous, from_env=True)
        with patch.dict(sys.modules, {"checkin": package}), patch.object(os, "environ", {
            "YAMIBO_USERNAME": "FAKE_INPUT_USER", "YAMIBO_PASSWORD": "FAKE_INPUT_PASSWORD"
        }), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = probe.run_probe(args, records.append)
        return code, records, output.getvalue()

    def assert_no_mutations(self, module):
        module.check_in.assert_not_called()
        module.query_stats.assert_not_called()
        module.send_message.assert_not_called()

    def test_challenge_stops_before_unrestricted_browser_entry(self):
        module = self.fake_module()
        original_playwright = module.sync_playwright
        code, records, _ = self.run_fake(module)
        self.assertEqual(original_playwright.call_count, 0,
                         "Probe must stop before entering the unrestricted Playwright factory")
        self.assertNotEqual(code, 0)
        self.assertTrue(any(r.get("error") == "browser_challenge_requires_separate_inspection"
                            for r in records))
        module.get_sign_page.assert_not_called()
        self.assert_no_mutations(module)

    def test_challenge_restores_session_credentials_and_factory(self):
        module = self.fake_module()
        original = {name: getattr(module, name) for name in
                    ("SESSION", "USERNAME", "PASSWORD", "sync_playwright")}
        self.run_fake(module)
        for name, value in original.items():
            self.assertIs(getattr(module, name), value, name)
        self.assert_no_mutations(module)

    def test_unexpected_failure_restores_state_and_hides_original_error(self):
        module = self.fake_module()
        original = {name: getattr(module, name) for name in
                    ("SESSION", "USERNAME", "PASSWORD", "sync_playwright")}
        def fail():
            print("FAKE_SENSITIVE_LEGACY_OUTPUT")
            raise RuntimeError("FAKE_SENSITIVE_ORIGINAL_EXCEPTION")
        module.login = fail
        code, records, output = self.run_fake(module)
        self.assertNotEqual(code, 0)
        self.assertNotIn("FAKE_SENSITIVE", output + json.dumps(records))
        for name, value in original.items():
            self.assertIs(getattr(module, name), value, name)
        self.assert_no_mutations(module)

    def test_module_without_playwright_attribute_is_supported(self):
        module = self.fake_module(browser=False)
        original_session = module.SESSION
        code, _, _ = self.run_fake(module)
        self.assertEqual(code, 1)
        self.assertFalse(hasattr(module, "sync_playwright"))
        self.assertIs(module.SESSION, original_session)
        self.assertEqual(module.USERNAME, "FAKE_ORIGINAL_USER")
        self.assertEqual(module.PASSWORD, "FAKE_ORIGINAL_PASSWORD")
        self.assert_no_mutations(module)

    def test_anonymous_success_restores_state_and_never_opens_browser(self):
        module = self.fake_module()
        original_session = module.SESSION
        original_playwright = module.sync_playwright
        code, _, _ = self.run_fake(module, anonymous=True)
        self.assertEqual(code, 0)
        self.assertIs(module.SESSION, original_session)
        self.assertIs(module.sync_playwright, original_playwright)
        original_playwright.assert_not_called()
        self.assertEqual(module.USERNAME, "FAKE_ORIGINAL_USER")
        self.assertEqual(module.PASSWORD, "FAKE_ORIGINAL_PASSWORD")
        self.assert_no_mutations(module)

if __name__ == "__main__":
    unittest.main(verbosity=2)
