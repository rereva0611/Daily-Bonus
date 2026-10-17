"""Anonymous browser compatibility research; no credentials or sign submissions.

Uses fresh default Chromium contexts, normal JavaScript and cookies. No stealth,
custom UA, stored profile, account login, or browser fingerprint overrides.
"""
from collections import Counter
import json
import re
from urllib.parse import parse_qsl, urlsplit
from playwright.sync_api import sync_playwright

URL = 'https://bbs.yamibo.com/plugin.php?id=zqlj_sign'


def emit(value):
    print(json.dumps(value, ensure_ascii=False), flush=True)


def category(url):
    try:
        parts = urlsplit(url)
        if parts.hostname == 'challenges.cloudflare.com' or parts.path.startswith('/cdn-cgi/challenge-platform/'):
            return 'cloudflare_challenge'
        if parts.hostname == 'bbs.yamibo.com':
            return 'yamibo'
    except ValueError:
        pass
    return 'other'


def forbidden_request(method, url):
    try:
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query))
        if 'sign' in query:
            return True
        if parts.hostname == 'bbs.yamibo.com' and parts.path in {'/member.php', '/home.php'}:
            return method != 'GET' or query.get('action') == 'logout'
        return False
    except ValueError:
        return True


def snapshot(page, response_state, mode, elapsed):
    body = page.content()
    cf_title = bool(re.search(r'<title>\s*(?:Just a moment(?:\.{3})?|Attention Required!\s*\|\s*Cloudflare)\s*</title>', body, re.I))
    cf_script = bool(re.search(r'cf-chl-|/cdn-cgi/challenge-platform|challenges\.cloudflare\.com', body, re.I))
    challenge = response_state.get('cf_mitigated') == 'challenge' or (cf_title and cf_script)
    login_marker = bool(re.search(r'member\.php[^\"\s<>]*action=login', body))
    logout_marker = bool(re.search(r'member\.php[^\"\s<>]*action=logout', body))
    parts = urlsplit(page.url)
    at_sign_page = parts.hostname == 'bbs.yamibo.com' and parts.path == '/plugin.php' and dict(parse_qsl(parts.query)).get('id') == 'zqlj_sign'
    has_sign_context = '我的打卡动态' in body or bool(re.search(r'class=[\"\']btna[\"\']', body))
    readable = bool(response_state.get('status') == 200 and at_sign_page and has_sign_context and not challenge)
    return {'stage':'browser_snapshot','mode':mode,'elapsed_seconds':elapsed,
            'status':response_state.get('status'), 'cloudflare_challenge':challenge,
            'at_sign_page':at_sign_page,'login_marker':login_marker,'logout_marker':logout_marker,
            'sign_context_present':has_sign_context,'anonymous_sign_page_readable':readable,
            'account_credentials_provided':False,'sign_submission_attempted':False}


def run_case(playwright, mode):
    response_state = {}
    responses = Counter()
    failures = Counter()
    blocked = Counter()
    options = {'headless':mode == 'chromium_headless'}
    if mode == 'chromium_headless':
        options['channel'] = 'chromium'
    elif mode == 'chrome_headed':
        options['channel'] = 'chrome'
    browser = playwright.chromium.launch(**options)
    try:
        context = browser.new_context()
        # This only blocks reward/account-changing endpoints; challenge resources
        # and their normal POST requests are allowed through Chromium unchanged.
        def route_request(route):
            if forbidden_request(route.request.method, route.request.url):
                blocked[category(route.request.url)] += 1
                route.abort()
            else:
                route.continue_()
        context.route('**/*', route_request)
        page = context.new_page()
        def note_response(response):
            responses[(category(response.url), response.request.resource_type, response.status)] += 1
            if response.request.is_navigation_request() and response.frame == page.main_frame:
                response_state.update(status=response.status, cf_mitigated=response.headers.get('cf-mitigated'))
        page.on('response', note_response)
        page.on('requestfailed', lambda request: failures.update([category(request.url)]))
        try:
            page.goto(URL, wait_until='domcontentloaded', timeout=25000)
        except Exception as error:
            emit({'stage':'navigation','mode':mode,'error_type':type(error).__name__})
        result = None
        for elapsed in range(0, 36, 5):
            if elapsed:
                page.wait_for_timeout(5000)
            result = snapshot(page, response_state, mode, elapsed)
            emit(result)
            if result['anonymous_sign_page_readable']:
                break
        emit({'stage':'network_summary','mode':mode,
              'responses':[{'category':key[0],'kind':key[1],'status':key[2],'count':count} for key,count in sorted(responses.items())],
              'failed_requests':dict(failures),'blocked_requests':dict(blocked),
              'storage_persisted':False,'normal_user_agent':True,'normal_javascript':True})
        return result
    finally:
        browser.close()


def main():
    results = []
    with sync_playwright() as playwright:
        for mode in ['chromium_headless', 'chromium_headed', 'chrome_headed']:
            try:
                results.append(run_case(playwright, mode))
            except Exception as error:
                emit({'stage':'case_error','mode':mode,'error_type':type(error).__name__})
    emit({'stage':'research_result','completed_cases':len(results),
          'readable_modes':[r['mode'] for r in results if r['anonymous_sign_page_readable']],
          'no_account_login':True,'no_sign_submission':True})
    # A challenge response is research data, not a successful check-in.
    return 0 if len(results) == 3 else 2


if __name__ == '__main__':
    raise SystemExit(main())
