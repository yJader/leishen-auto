# Authentication Renewal Feasibility

Tested 2026-10-25 against the current public Leigod website and again from a
GitHub Actions runner. No real account, password, or token was used.

The current `www.leigod.com` client uses the signed
`POST /api/auth/login/v2` endpoint. Its password-login flow obtains a
Geetest/Tencent behavior-verification result before submitting the password.
The public setting endpoint returned `is_off_geetest_login=1`, and a
synthetic request without verification returned `400001: 验证码不能为空`.
The public system-time endpoint returned success, confirming the API was
reachable. The older `/api/auth/login/v1` and `/api/auth/login` probes were
blocked by CloudWAF with HTTP 418, so they are not a verified fallback.

**Conclusion:** a fresh `account_token` can be issued by logging in, but the
current password-login flow cannot be completed unattended by this workflow
because it requires an interactive behavior challenge. This test did not
attempt to solve or bypass that challenge. There is no evidence of a separate
refresh-token endpoint in the current public client bundle.

GitHub Actions synthetic probe: [run 40181682201](https://github.com/yJader/leishen-auto/actions/runs/40181682201).
The repeatable, credential-free probe is `scripts/auth_probe.py`. It only logs
response status, public setting data, and whether a token appeared; it does not
persist login responses or perform account actions.
