#!/usr/bin/env python3
"""Test observed Leigod login endpoints using a synthetic account, without user secrets.

A zero exit code means the diagnostic finished, not that authentication succeeded.
No CAPTCHA is solved and no pause, login-state mutation, or Secret update is performed.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

PAGE = 'https://www.leigod.com/'
API = 'https://webapi.leigod.com'


def fetch(url):
    with urllib.request.urlopen(url, timeout=20) as response:
        return response.read()


def request(path, payload=None):
    req = urllib.request.Request(
        API + path, data=json.dumps(payload).encode() if payload is not None else None,
        headers={'Content-Type': 'application/json', 'Origin': PAGE.rstrip('/'),
                 'Referer': PAGE, 'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
    except (urllib.error.URLError, TimeoutError) as error:
        return {'path': path, 'transport_error': type(error).__name__}
    result = {'path': path, 'http_status': status}
    try:
        data = json.loads(body)
        if not isinstance(data, dict):
            result['invalid_response_type'] = True
            return result
        result.update(code=data.get('code'), msg=data.get('msg'))
        # Only expose this public setting; never persist login responses or tokens.
        if path == '/tools/setting/list':
            result['data'] = data.get('data')
        result['token_received'] = bool(
            isinstance(data.get('data'), dict)
            and (data['data'].get('login_info') or {}).get('account_token'))
    except (ValueError, UnicodeDecodeError):
        result.update(json_response=False,
                      cloudwaf=b'CloudWAF' in body or '访问被拦截'.encode() in body)
    return result


def discover():
    html = fetch(PAGE).decode()
    src = re.search(r'<script[^>]*src="(/_assets/[^\"]+\.js)"', html)
    if not src:
        raise RuntimeError('Cannot find official main bundle; stop rather than guess protocol')
    url = PAGE.rstrip('/') + src.group(1)
    bundle = fetch(url)
    match = re.search(r'eT=\(e,t="([A-F0-9]{32})"', bundle.decode())
    if not match or b'/webapi/api/auth/login/v2' not in bundle:
        raise RuntimeError('Official login protocol changed; inspect the new source')
    return match.group(1), {'url': url, 'sha256': hashlib.sha256(bundle).hexdigest()}


def sign(payload, key):
    payload = dict(payload, ts=str(int(time.time())))
    # Official JS signs raw values, sorted keys, then appends its public web key.
    raw = '&'.join(f'{name}={payload[name]}' for name in sorted(payload)) + '&key=' + key
    payload['sign'] = hashlib.md5(raw.encode()).hexdigest()
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    key, source = discover()
    common = {'region_code': 1, 'src_channel': 'guanwang', 'lang': 'zh_CN', 'os_type': 4}
    payload = dict(common, username='auth-probe@example.invalid',
                   mobile_num='auth-probe@example.invalid', country_code=86,
                   password=hashlib.md5(b'not-a-real-account-password').hexdigest())
    results = [request('/tools/system_time'),
               request('/tools/setting/list', dict(common, key_name='is_off_geetest_login')),
               request('/api/auth/login/v2', sign(payload, key))]
    # Legacy paths are still present on vip.leigod.com, inspected separately.
    for path, signed in [('/api/auth/login/v1', True), ('/api/auth/login', False)]:
        legacy = dict(common, username=payload['username'], password=payload['password'],
                      user_type='0', code='')
        results.append(request(path, sign(legacy, key) if signed else legacy))
    output = {'tested_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'mode': 'synthetic-account', 'source': source, 'results': results,
              'real_login_verified': False,
              'note': 'No real account used; probe success does not mean login succeeded.'}
    rendered = json.dumps(output, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
