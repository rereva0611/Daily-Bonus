import unittest
from unittest.mock import Mock
from test_browser_probe_policy import module


class BrowserContextGuardTests(unittest.TestCase):
    def test_service_workers_are_always_blocked(self):
        browser = Mock()
        module.BrowserProxy(browser).new_context(user_agent='test-agent', service_workers='allow')
        browser.new_context.assert_called_once_with(user_agent='test-agent', service_workers='block')
        browser.new_context.return_value.route.assert_called_once()

    def test_nondefault_and_invalid_ports_are_rejected(self):
        for url in ('https://bbs.yamibo.com:8443/forum.php',
                    'https://bbs.yamibo.com:bad/forum.php',
                    'https://bbs.yamibo.com:99999/forum.php',
                    'https://[invalid/forum.php'):
            with self.subTest(url=url):
                self.assertFalse(module.allowed_browser_request('GET', url, 'document'))
        self.assertTrue(module.allowed_browser_request('GET', 'https://bbs.yamibo.com:443/forum.php', 'document'))


if __name__ == '__main__':
    unittest.main()
