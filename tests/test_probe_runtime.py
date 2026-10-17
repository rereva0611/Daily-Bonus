import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(os.environ.get("YAMIBO_PROBE_SOURCE", ROOT / "tools/yamibo_probe.py"))
spec = importlib.util.spec_from_file_location("runtime_probe", TARGET)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class RuntimeTests(unittest.TestCase):
    def run_guest(self):
        guest = '<a href="member.php?mod=logging&action=login">登录</a><a class="btna" href="plugin.php?id=zqlj_sign&sign=abcdef12">点击打卡</a>'
        response = SimpleNamespace(text=guest, status_code=200,
            url="https://bbs.yamibo.com/plugin.php?id=zqlj_sign", headers={})
        class Session:
            def get(self, *args, **kwargs):
                return response
        yamibo = SimpleNamespace(SESSION=Session(), login=lambda: True,
                                 USERNAME=None, PASSWORD=None)
        def get_sign_page():
            yamibo.SESSION.get(response.url)
            print("FAKE_SENSITIVE_LEGACY_OUTPUT")
            return "abcdef12", False, guest
        yamibo.get_sign_page = get_sign_page
        package = ModuleType("checkin")
        package.yamibo = yamibo
        output = io.StringIO()
        with patch.dict(sys.modules, {"checkin": package}), patch.object(sys, "argv", ["probe", "--from-env"]), patch.object(os, "environ", {"YAMIBO_USERNAME":"FAKE_USER", "YAMIBO_PASSWORD":"FAKE_PASSWORD"}), contextlib.redirect_stdout(output):
            code = probe.main()
        return code, output.getvalue()

    def test_guest_does_not_pass_if_legacy_parser_accepts(self):
        code, _ = self.run_guest()
        self.assertEqual(code, 1)

    def test_metadata_visible_but_legacy_prints_hidden(self):
        _, output = self.run_guest()
        self.assertNotIn("FAKE_SENSITIVE_LEGACY_OUTPUT", output)
        records = [json.loads(line) for line in output.splitlines()]
        self.assertTrue(any(r.get("stage") == "sign_page" for r in records))

    def test_observed_nox_405_challenge(self):
        response = SimpleNamespace(text='<script src="/_nox/challenge.js"></script>',
            status_code=405, url="https://bbs.yamibo.com/forum.php", headers={})
        self.assertEqual(probe.summarize(response, "forum")["classification"], "challenge")


if __name__ == "__main__":
    unittest.main()
