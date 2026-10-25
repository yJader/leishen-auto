#!/usr/bin/env python3
"""Probe Leigod's observed web login protocol; never print credentials or tokens."""
import argparse
import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

LOGIN_PAGE = 'https://vip.leigod.com/login.html'
API_BASE = 'https://webapi.leigod.com'


def request_json(path, payload):
    req = urllib.request.Request(
        API_BASE + path, data=json.dumps(payload).encode(), method='POST',
        headers={'Content-Type': 'application/json', 'Origin': 'https://vip.leigod.com',
                 'Referer': LOGIN_PAGE, 'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
    except (urllib.error.URLError, TimeoutError) as error:
        return {'path': path, 'transport_error': type(error).__name__}, None
    summary = {'path': path, 'http_status': status}
    try:
        data = json.loads(body)
        if not isinstance(data, dict):
            summary['invalid_response_type'] = True
            return summary, None
        summary['code'] = data.get('code')
        # Arbitrary server messages can echo credentials; only print known messages.
        known_messages = ['验证码', '登录态', '账号或密码', '用户名或密码', '签名', '短信', '成功', '账户不存在', '账号不存在']
        message = str(data.get('msg', ''))
        summary['message_categories'] = [word for word in known_messages if word in message]
        summary['data_keys'] = sorted(data['data']) if isinstance(data.get('data'), dict) else []
        return summary, data
    except (ValueError, UnicodeDecodeError):
        summary['json_response'] = False
        summary['cloudwaf'] = b'CloudWAF' in body or '访问被拦截'.encode() in body
        return summary, None


def discover():
    with urllib.request.urlopen(LOGIN_PAGE, timeout=20) as response:
        html = response.read().decode()
    src = re.search(r'src="(/js/chunk-common\.js[^\"]*)"', html)
    if not src:
        raise RuntimeError('Cannot find official common bundle; stop rather than guess protocol')
    url = 'https://vip.leigod.com' + src.group(1)
    with urllib.request.urlopen(url, timeout=20) as response:
        bundle = response.read()
    match = re.search(r'key:"([A-F0-9]{32})"', bundle.decode())
    if not match:
        raise RuntimeError('Official request-signing protocol changed')
    return match.group(1), {'url': url, 'sha256': hashlib.sha256(bundle).hexdigest()}


def sign(payload, key):
    payload = dict(payload, ts=str(int(time.time())))
    # Official JS uses raw values, sorted keys, then appends the public web key.
    raw = '&'.join(f'{name}={payload[name]}' for name in sorted(payload)) + '&key=' + key
    payload['sign'] = hashlib.md5(raw.encode()).hexdigest()
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--real-account', action='store_true', help='Read LEISHEN_USERNAME/PASSWORD or prompt securely; log in once, then read user info')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    key, source = discover()
    if args.real_account:
        username = os.environ.get('LEISHEN_USERNAME')
        password = os.environ.get('LEISHEN_PASSWORD')
        if not username or not password:
            if not sys.stdin.isatty():
                parser.error('Real account mode requires both credential environment variables or an interactive terminal')
            username = username or input('Leigod account: ').strip()
            password = password or getpass.getpass('Leigod password (hidden): ')
        if not username or not password:
            parser.error('Credentials must be nonempty')
    else:
        username, password = 'auth-probe@example.invalid', 'not-a-real-account-password'
    payload = {'username': username, 'password': hashlib.md5(password.encode()).hexdigest(),
               'user_type': '0', 'src_channel': '', 'code': '', 'lang': 'zh_CN', 'os_type': 4}
    if username.isdigit():
        payload['country_code'] = '86'
    results = []
    paths = [('/api/auth/login/v1', True)] if args.real_account else [('/api/auth/login/v1', True), ('/api/auth/login', False)]
    success = False
    for path, signed in paths:
        summary, response = request_json(path, sign(payload, key) if signed else payload)
        summary['signed'] = signed
        results.append(summary)
        if args.real_account and response and response.get('code') == 0:
            data = response.get('data') or {}
            login_info = data.get('login_info') or {}
            token = login_info.get('account_token')
            summary['token_received'] = bool(token)
            summary['login_info_keys'] = sorted(login_info)
            if token:
                info_summary, info = request_json('/api/user/info', {'account_token': token, 'lang': 'zh_CN', 'os_type': 4})
                results.append(info_summary)
                success = bool(info and info.get('code') == 0)
    output = {'tested_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'mode': 'real-account' if args.real_account else 'synthetic-account',
              'source': source, 'results': results, 'real_login_verified': success}
    rendered = json.dumps(output, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + '\n')
    return 0 if not args.real_account or success else 1


if __name__ == '__main__':
    sys.exit(main())
