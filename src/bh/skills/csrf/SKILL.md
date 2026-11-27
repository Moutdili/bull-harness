---
name: csrf
description: Use when a state-changing request on your own account works with a cookie session (profile, e-mail, password, settings). Decides whether a cross-site page could send it: the browser judges, not curl.
---
<!--
Source: hermes/bug-bounty/csrf-cross-site-request-forgery/SKILL.md; merged from hermes/bug-bounty/csrf-modern and hermes/bug-bounty/bug-bounty-proof-package (its CSRF rule and references/csrf-validation.md). No author or licence stated; the sources point to PortSwigger Web Security Academy (CSRF, bypassing SameSite restrictions) and the OWASP CSRF prevention cheat sheet.
Modified: translated; bound to our own identities; hosted PoC pages, "victim clicks a link" steps and real target names removed.
Role: hunter. No class id for CSRF exists yet in our classes (see out/README.md).
False positives merged from Strix strix/skills/vulnerabilities/csrf.md (Copyright 2025 OmniSecure Inc., Apache-2.0).
Modified from Strix (Apache-2.0) by bull-harness: its "False Positives" lines rewritten into ours (marked "(Strix)").
modified (bull-harness W3-H): payload host `<marker>.<payload-host>` in step 2; the unmeasured line on cookie
attributes seen through the gate removed (not measured); class standard now in classes_more.json.
-->

# CSRF

## When
- A POST, PUT, PATCH, DELETE, or a GET that changes state, succeeds on your own object and the session
  travels in a cookie.
- Not when the API authenticates with an `Authorization` header only: a cross-site page cannot add it.
  Record `bh-note fact "<origin>: header auth, no CSRF surface" -k dead-end`.

## Do
1. Cookie policy first. Read the `Set-Cookie` line of the session cookie on an authenticated answer
   (`q -a user-a -i -n 0 <a page of your account>`).
   - `SameSite=None`: sent cross-site. CSRF is possible.
   - `Lax`, or no attribute: not sent on a cross-site POST. Only a state-changing GET by top-level
     navigation remains.
   - `Strict`: not sent cross-site. Only a redirect inside the site that leads to the action remains.
2. Is the token read? Three sends on your own object, as user-a:
   a. with the valid token: positive control;
   b. without the token;
   c. with a wrong token of the same length.
   On b and c send `-H 'Origin: https://<marker>.<payload-host>' -H 'Referer: https://<marker>.<payload-host>/poc.html'`,
   do not only omit them (`<payload-host>`: the payload hosts of your scope block; none listed in your scope block:
   `bh-note blocked other "no payload host declared"`). b and c both succeed = the control does not exist. c
   succeeding is the stronger proof.
3. Read the effect on the server side: `q -a user-a <url of the object>`. Never trust the status alone.
4. Variants, one request each, only if step 2 was refused:
   - the same action sent as GET (method not checked);
   - `Content-Type: text/plain` carrying the JSON body (no preflight);
   - user-b's valid token on user-a's request (token not bound to the session; both are yours).
5. Impact before recording: cart or preference = low, often informative; address or contact data = medium;
   e-mail, password, payment = high. Test the three writes that matter most, not all of them.
6. Put your object back as it was.

## Proof
proof.json, all on your own object:
- `setup`: read the object, old value;
- `attack`: as user-a, the forged request (no token, foreign Origin and Referer, a marker in the body),
  expecting success; then a read step expecting the marker;
- `control`: the same forged request with `"as": null`, expecting 401, 403 or a redirect to login (the action
  needs the victim's cookie).
Attach the `Set-Cookie` line as evidence (`-e`). In `--not-proven`: "no browser ran a cross-site page; rests on
SameSite=<value> read at <UTC time>".

## Never
- Host a PoC page anywhere or send a link to anyone. The only victim is your own identity.
- Change an e-mail or password to a value you cannot revert, or lock a test account.
- Loop over every write endpoint.

## False positives
- curl succeeding proves nothing: curl sends the cookie whatever `SameSite` says.
- `HttpOnly` and `Secure` do not affect CSRF.
- Cross-origin is not cross-site: a sibling subdomain shares the site.
- A 403 from the WAF on your payload is not the application's CSRF control.
- A controller that routes only with `X-Requested-With: XMLHttpRequest` answers a 200 "not found" page
  without it. Compare sizes and content types before concluding. If the header is required, a cross-site form
  cannot set it: that is a control.
- Login, logout and public-form CSRF are excluded on most programs.
- (Strix) A token or an `Origin`/`Referer` check that refuses every forged send of steps 2 and 4: the control
  works, consistently.
- (Strix) `SameSite=Strict` (or no cookie on a cross-site request) and no state change reachable by a simple
  request: nothing a cross-site page can send.
- (Strix) Only idempotent, non-sensitive operations affected: a read, a harmless preference.

## Watch
- A site may set the cookie without `SameSite` on the first visit and `None` later: read it on a second,
  authenticated answer.
- The same missing check on several controllers of one application is one root cause.
