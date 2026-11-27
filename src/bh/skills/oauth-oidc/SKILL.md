---
name: oauth-oidc
description: Use when an in-scope app signs users in or links accounts with OAuth or OpenID Connect and its authorization server is in scope. Checks redirect_uri, state, PKCE and token audience on your own login.
---
<!--
Source: strix/skills/protocols/oauth.md, Strix (https://github.com/usestrix/strix), Copyright 2025 OmniSecure Inc.,
Apache License 2.0.
Also: inputs/skills-audit/FUSIONS.md, section "Classes T41", row "OAuth / OIDC" (Hermes oauth-attacks,
oauth2-attacks, oidc-attacks, no licence stated): redirect_uri forms, absent state, empty code_verifier, the return
page that calls window.opener, nonce, userinfo with the other account's token, and the two false positives.
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form, bound to our two identities and to an
authorization server in scope; removed: "fuzz redirect_uri" matrices, client enumeration from public repositories,
dynamic client registration with our own redirect, device-code guessing, Referer harvesting from an attacker page,
mobile scheme hijacking, the "Tooling" section (a tool we do not have), the "Pro Tips" list.
-->

# OAuth 2.0 / OpenID Connect

## When
- The app's login or "connect your account" sends the browser to `/authorize` (or `/oauth2/authorize`) and comes
  back to a callback with `code` (or a token in the fragment).
- The authorization server is a host of your scope. A third-party identity provider, or any host the scope marks
  as a login host, is never a target: the gate refuses it; record it and stop.
- Discovery, one request: `q -n 2000 <issuer>/.well-known/openid-configuration` (endpoints, response types,
  `code_challenge_methods_supported`).

## Do
1. The flow as the app runs it: the authorize URL and its parameters (`client_id`, `redirect_uri`, `state`,
   `code_challenge`, `nonce`, `scope`), from `bh-web net` or a `bh-browse` summary. Never drive a login: use what
   the browser tools recorded.
2. `redirect_uri`, one change per request, as your identity, on the authorize URL (redirects are not followed):
   a path appended (`<callback>/bhx12345`), a suffix host (`<callback host>.<payload-host>`), `@<payload-host>`,
   an encoded slash or `..`, a second `redirect_uri`. Read the `Location` header: a `code` or token sent to a
   place you chose = the lead. `<payload-host>`: the payload hosts of your scope block; none listed in your scope
   block: `bh-note blocked other "no payload host declared"`.
3. `state`: the authorize request without it, or with a fixed value. Accepted and the callback also accepts it =
   login CSRF candidate (an account-linking flow raises it: the other identity's provider account linked to
   yours).
4. PKCE, on a public client (SPA, mobile): the authorize URL without `code_challenge`, or with
   `code_challenge_method=plain`. Then the token exchange of a code you hold with an empty or wrong
   `code_verifier`. Accepted = PKCE not enforced.
5. Tokens: the access token issued to your identity for this app, sent to another API of the same program
   (audience); `userinfo` with your other identity's token must answer that identity, never yours.
6. The callback page: does it call `window.opener.postMessage` with the code or token and target `*`? Read the
   page's script (skill `postmessage` for the test).

## Proof
proof.json on your own login, the code or token never leaves our hosts:
- `attack`: the authorize request with the changed `redirect_uri` (or without `state`, or without PKCE), as your
  identity, expecting a `Location` that carries `code=` toward the place you chose (or the accepted exchange);
- `control`: the same request with the registered `redirect_uri` changed in a way the server must refuse (a
  foreign host), or with the valid `state` / `code_verifier`, expecting the refusal or the registered callback.
In `--not-proven`: "no code was redeemed by a third party; the redirect was read, not followed".

## Never
- Follow a redirect that carries a code or a token, or redeem a code anywhere but at the app's own token endpoint.
- Register a client, or a redirect, on the authorization server.
- Guess device codes, user codes or `state` values.
- Use a token, code or account that is not one of your identities.

## False positives
- (Hermes, Strix) A public client (SPA, mobile) without a client secret: that is the design; PKCE protects it.
- (Hermes, Strix) A `redirect_uri` the server validates on its side and refuses in every form you sent.
- (Strix) `state` or `nonce` enforced and bound to the session: the CSRF test fails as it should.
- (Strix) Correctly bound PKCE (S256, verifier checked) also protects against login CSRF without `state`.
- (Strix) Token audience and issuer checked by the resource server.
- A redirect to another path of the registered host only, which you do not control.

## Watch
- Many programs pay an open redirect on the callback only when it leaks a code: chain with the card
  `open-redirect` (skill `chaining`).
- An account-linking flow without `state` is the strongest form: show it between your two identities only.
- JWT access tokens: the skill `jwt` for the token itself.
