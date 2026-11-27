---
name: auth
description: Use when testing login, tokens, sessions, password reset, 2FA, or admin and role routes; or when an identity's session holds a JWT.
---
<!-- Source: card src/bh/cards/auth.md (ours), plus the lines FUSIONS.md (skills audit, W3-C) drew from the Hermes
skills bug-bounty/2fa-mfa-bypass, bug-bounty/jwt-attacks, security/api-security, bug-bounty/session-cookie-attacks,
bug-bounty/password-reset-asterion04 and bug-bounty/host-header-attacks (no licence stated). Modified: roles left
free; removed: cracking a JWT secret, loops over 2FA codes, editing answers in a proxy. -->
# Authentication and session

## When
- Login, token, password reset, 2FA, admin or role routes; JWTs in identity sessions.
- Routes found by `bh-crawl` or `bh-js` under `/admin`, `/role`, `/me`, `/whoami`, `/session`.

## Do
1. Map which routes need a session: the same request with and without an identity (`q -a <identity> <url>`, then
   `q <url>`); expect 401/403 without.
2. Tokens: decode JWTs locally (`cut -d. -f2 | base64 -d`), check `alg`, `kid`, expiry, role claims. Try
   `alg: none` and a modified claim ONLY with your own identity's token. If the public key is published (JWKS),
   try your own token re-signed as HS256 with that key; check that `kid` and `jku` are not taken from the token;
   try a token without `exp`. More: skill `jwt`.
3. Session handling: does logout invalidate the token? Does a password change kill other sessions? Does the session
   id change at login (fixation)? Is a session of one application accepted by a sibling application? (own accounts
   only)
4. 2FA on one of our identities: call an authenticated API route right after the password step, without the code;
   the same code twice; a login path (OAuth, SSO) that never asks for the code; does a password reset switch 2FA
   off? OAuth and SSO flows: skills `oauth-oidc` and `saml`.
5. Reset between our two identities: one identity's token on the other's reset; an empty or `null` token; another
   method or content type; a token bound to the right account; a step skipped. A reset link built from
   `X-Forwarded-Host` only shows in the mail: `bh-note blocked other "reset host only in the mail" --tried "<...>"
   --would-prove "<...>"`. Type changes on the e-mail field: skill `type-confusion`.
6. Role checks: a user-level identity calling the admin-looking routes found by `bh-crawl` (skill
   `function-level-authz`).

## Proof
A resource or action reserved to an authenticated or more privileged user, reached without the needed credentials.
proof.json: attack on the route with the bypass (`"as": null`, or the lower identity), expecting the protected
marker; twin control, same method and URL, without the bypass (another query or body), expecting
`{"status": [401, 403]}`. A forged token travels in `Authorization` or `Cookie`, which proof.json refuses: then
`bh-note fact "CANDIDATE: <title>" -s "<request, claims changed, the two answers>" -e <file>`, never a finding
written without a replayable proof.
`bh-note finding "<title>" --severity <s> --class auth --url <url> --proof proof.json --summary "<...>"
--not-proven "<...>" --counter "<...>" --severity-if "<...>" --severity-why "<...>"`.

## Never
- Guess other users' passwords or OTPs (brute force is excluded everywhere), lock out real accounts.
- Loop over codes or tokens, even to show that no limit exists.
- Use a token that is not one of our identities', or start a sign-in on a login host (support hosts are never
  targets).

## False positives
- A token the attacker obtained legitimately is not a bypass.
- A 200 that is the sign-in page or the app shell; a redirect to the login page.
- A session that survives logout only on the client (the server refuses it): replay it with `q` before you conclude.

## Watch
- An `alg: none` token accepted only on a route that answers the same thing anonymously proves nothing.
- Claims the server ignores (it reads the role from its database): change one claim, compare, move on.
- Order of checks: a 400 before the 401 says the route parses before it authenticates, not that it is open.
