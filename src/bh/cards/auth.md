## Authentication and session
When: login, token, password reset, 2FA, admin or role routes; JWTs in identity sessions.
Do:
1. Map which routes need a session: same request with and without `X-BH-Identity` (expect 401/403 without).
2. Tokens: decode JWTs locally (`cut -d. -f2 | base64 -d`), check `alg`, `kid`, expiry, role claims. Try `alg: none`
   and a modified claim ONLY with your own identity's token.
3. Session handling: does logout invalidate the token? does a password change kill other sessions? (own accounts only)
4. Reset / 2FA flows on user-a: token reuse, token bound to the right account, step skipping.
5. Role checks: user-level identity calling admin-looking routes found by bh-crawl.
Never: guess other users' passwords or OTPs (brute force is excluded everywhere), lock out real accounts.
