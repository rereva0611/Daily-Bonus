import contextlib
from http.cookiejar import Cookie, CookieJar
import importlib.util
import io
import inspect
import json
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(os.environ.get("YAMIBO_ROUTE_PROBE_SOURCE", str(ROOT / "tools/yamibo_route_probe.py")))
fake_package = ModuleType("checkin")
fake_package.yamibo = SimpleNamespace(sync_playwright=Mock())
spec = importlib.util.spec_from_file_location("route_probe_test_target", TARGET)
p = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"checkin": fake_package}):
    spec.loader.exec_module(p)

HOST = "bbs.yamibo.com"
SIGN = "https://bbs.yamibo.com/plugin.php?id=zqlj_sign"
READY = '<a href="member.php?mod=logging&action=logout">退出</a><a class="btna" href="plugin.php?id=zqlj_sign&sign=abcdef">点击打卡</a>'


def cookie(domain, name="fake", value="FAKE_COOKIE_VALUE"):
    return Cookie(0, name, value, None, False, domain, True, domain.startswith("."),
                  "/", True, True, None, True, None, None, {"HttpOnly": None}, False)


def response(body, status=200, url=SIGN):
    return SimpleNamespace(text=body, status_code=status, url=url, headers={"content-type":"text/html"})


class RouteTests(unittest.TestCase):
    def api(self, name):
        self.assertTrue(callable(getattr(p, name, None)), "Missing diagnostic API: " + name)
        return getattr(p, name)

    def test_precise_sign_document_allowed(self):
        self.assertTrue(p.allowed_browser_request("GET", SIGN, "document"))

    def test_dynamic_script_route_is_blocked(self):
        self.assertFalse(p.allowed_browser_request("GET", "https://bbs.yamibo.com/misc.php", "script"))

    def test_static_only_without_extra_query(self):
        self.assertTrue(p.allowed_browser_request("GET", "https://bbs.yamibo.com/static/js/a.js", "script"))
        for url in (SIGN + "&sign=abc", SIGN + "&id=other", "https://bbs.yamibo.com/static/a.js?sign=abc",
                    "https://bbs.yamibo.com/static/a.php", "https://evil.invalid/static/a.js",
                    "https://bbs.yamibo.com/static/../misc.js", "https://bbs.yamibo.com/static/%2e%2e/misc.js"):
            self.assertFalse(p.allowed_browser_request("GET", url, "script"), url)
        self.assertFalse(p.allowed_browser_request("POST", SIGN, "document"))

    def test_redirects_are_not_followed(self):
        install = self.api("install_browser_guard")
        context, page = Mock(), Mock()
        state = {"blocked_requests":0, "blocked_redirects":0}
        install(context, page, state)
        cdp = context.new_cdp_session.return_value
        cdp.on.call_args.args[1]({"requestId":"FAKE_REQUEST", "responseStatusCode":302})
        cdp.send.assert_any_call("Fetch.failRequest", {"requestId":"FAKE_REQUEST", "errorReason":"BlockedByClient"})
        self.assertEqual(state["blocked_redirects"], 1)
        cdp.send.assert_any_call("Fetch.enable", {"patterns":[{"urlPattern":"*","requestStage":"Response"}]})

    def test_forbidden_route_never_fetches(self):
        install = self.api("install_browser_guard")
        context, page = Mock(), Mock()
        state = {"blocked_requests":0, "blocked_redirects":0}
        install(context, page, state)
        route = Mock()
        route.request = SimpleNamespace(method="GET", url=SIGN + "&sign=abc", resource_type="document", frame=SimpleNamespace(page=page))
        context.route.call_args.args[1](route)
        route.fetch.assert_not_called()
        route.continue_.assert_not_called()
        route.abort.assert_called_once()
        self.assertEqual(state["blocked_requests"], 1)

    def test_allowed_route_uses_browser_network(self):
        install = self.api("install_browser_guard")
        context, page = Mock(), Mock()
        state = {"blocked_requests":0, "blocked_redirects":0}
        install(context,page,state)
        route = Mock()
        route.request = SimpleNamespace(method="GET", url=SIGN, resource_type="document", frame=SimpleNamespace(page=page))
        context.route.call_args.args[1](route)
        route.continue_.assert_called_once()
        route.fetch.assert_not_called()
        context.route_web_socket.assert_called_once()

    def test_cookie_export_rejects_foreign_and_broad_domains(self):
        export = self.api("browser_cookies")
        jar = CookieJar()
        for domain in (HOST, ".yamibo.com", ".com", "evil.invalid", "yamibo.com.evil.invalid", ""):
            jar.set_cookie(cookie(domain))
        session = SimpleNamespace(cookies=SimpleNamespace(jar=jar))
        result = export(session)
        self.assertEqual({item["domain"] for item in result}, {HOST, ".yamibo.com"})
        self.assertTrue(all(item["secure"] for item in result))
        self.assertTrue(all(item["httpOnly"] for item in result))

    def test_cookie_import_rejects_foreign_domains(self):
        copy = self.api("copy_browser_cookies")
        jar = CookieJar()
        session = SimpleNamespace(cookies=SimpleNamespace(jar=jar))
        count = copy(session, [{"name":"good","value":"FAKE_COOKIE", "domain":".yamibo.com", "path":"/", "secure":True},
                               {"name":"bad","value":"FAKE_COOKIE", "domain":".com", "path":"/"},
                               {"name":"bad","value":"FAKE_COOKIE", "domain":"other.yamibo.com", "path":"/"}])
        self.assertEqual(count, 1)
        self.assertEqual([(c.name, c.domain) for c in jar], [("good", ".yamibo.com")])

    def test_denial_metadata_has_only_fixed_provider_values(self):
        summarize = self.api("summarize")
        r = response('<title>Access Denied</title><p>FAKE_PRIVATE_HTML</p><script>cf-chl-</script>',403)
        r.headers.update({"server":"cloudflare", "cf-ray":"FAKE_PRIVATE_HEADER", "x-private":"FAKE_PRIVATE_HEADER"})
        result = summarize(r,"browser_sign_page")
        self.assertTrue(result["access_denied_marker"])
        self.assertEqual(result["server_provider"], "cloudflare")
        self.assertTrue(result["cloudflare_marker"])
        self.assertNotIn("FAKE_PRIVATE", json.dumps(result))
        self.assertFalse(result["authenticated_sign_page_readable"])
        r.headers["server"] = "FAKE_PRIVATE_SERVER"
        self.assertEqual(summarize(r,"x")["server_provider"],"other")

    def flow(self, fail=False):
        run = self.api("run_authenticated")
        self.assertIn("yamibo_module", inspect.signature(run).parameters, "Need isolated module injection for a network-free diagnostic test")
        yamibo = ModuleType("fake_yamibo")
        session = Mock()
        session.cookies.jar = CookieJar()
        session.cookies.jar.set_cookie(cookie(".yamibo.com"))
        signs = iter([response("<title>403 Forbidden</title>",403), response(READY)])
        def get(url, **kwargs):
            return response(READY, url=url) if url.endswith("forum.php") else next(signs)
        session.get.side_effect = get
        yamibo.SESSION = session
        yamibo.USERNAME, yamibo.PASSWORD = "ORIGINAL_FAKE_USER", "ORIGINAL_FAKE_PASSWORD"
        yamibo.HEADERS = {"user-agent":"FAKE_UA"}
        yamibo.msg = [{"name":"original","value":"preserved"}]
        yamibo.check_in, yamibo.query_stats = Mock(), Mock()
        yamibo.sync_playwright = MagicMock()
        browser = yamibo.sync_playwright.return_value.__enter__.return_value.chromium.launch.return_value
        context = browser.new_context.return_value
        page = context.new_page.return_value
        page.goto.return_value = SimpleNamespace(status=200, headers={"content-type":"text/html"})
        page.content.return_value = READY
        page.url = SIGN
        context.cookies.return_value = [{"name":"fresh","value":"FAKE_NEW_COOKIE", "domain":".yamibo.com", "path":"/", "secure":True}]
        if fail:
            page.goto.side_effect = RuntimeError("FAKE_PRIVATE_EXCEPTION")
        yamibo.login = Mock(return_value=True)
        def sign_page():
            yamibo.SESSION.get(SIGN)
            return None, None, None
        yamibo.get_sign_page = Mock(side_effect=sign_page)
        old = {key:getattr(yamibo,key) for key in ("SESSION","USERNAME","PASSWORD","sync_playwright","check_in","query_stats","msg")}
        records=[]
        out=io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code=p.run_authenticated("FAKE_INPUT_USER","FAKE_INPUT_PASSWORD",records.append,yamibo_module=yamibo)
        return yamibo,session,browser,context,page,old,records,out.getvalue(),code

    def test_three_evidence_stages_cookie_transfer_and_guards(self):
        y,s,b,c,page,old,records,out,code=self.flow()
        self.assertEqual(code,0)
        stages=[r.get("stage") for r in records]
        for stage in ("post_login_forum","sign_page","browser_sign_page","cffi_sign_page_after_browser"):
            self.assertIn(stage,stages)
        summary=next(r for r in records if r.get("stage")=="comparison")
        self.assertTrue(summary["browser_readable"])
        self.assertTrue(summary["cffi_after_cookie_copy_readable"])
        c.add_cookies.assert_called_once()
        self.assertEqual(b.new_context.call_args.kwargs["user_agent"],"FAKE_UA")
        self.assertEqual(b.new_context.call_args.kwargs["service_workers"],"block")
        page.goto.assert_called_once_with(SIGN,wait_until="networkidle",timeout=30000)
        self.assertEqual(sum(call.args[0]==SIGN for call in s.get.call_args_list),2)
        self.assertEqual(sum(call.args[0].endswith("forum.php") for call in s.get.call_args_list),1)
        self.assertTrue(any(item.name=="fresh" for item in s.cookies.jar))
        y.check_in.assert_not_called(); y.query_stats.assert_not_called()
        self.assertNotIn("FAKE_NEW_COOKIE",json.dumps(records)+out)
        for key,value in old.items(): self.assertIs(getattr(y,key),value,key)
        b.close.assert_called_once()

    def test_browser_failure_restores_globals_and_is_safe_nonzero(self):
        y,s,b,c,page,old,records,out,code=self.flow(fail=True)
        self.assertNotEqual(code,0)
        self.assertNotIn("FAKE_PRIVATE_EXCEPTION",json.dumps(records)+out)
        self.assertEqual(sum(call.args[0]==SIGN for call in s.get.call_args_list),1)
        y.check_in.assert_not_called(); y.query_stats.assert_not_called()
        for key,value in old.items(): self.assertIs(getattr(y,key),value,key)
        b.close.assert_called_once()

if __name__=="__main__": unittest.main(verbosity=2)
