---
name: nextjs
description: Use when the target is a Next.js app (`/_next/static/`, `__NEXT_DATA__`, `Next-Action` requests). Maps routes and server actions, then tests middleware, props and caching per identity.
---
<!--
Source: strix/skills/frameworks/nextjs.md, Strix (https://github.com/usestrix/strix), Copyright 2025 OmniSecure Inc.,
Apache License 2.0.
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form, between our two identities; its
"Validation Requirements" turned into our Proof and False positives; removed: browser-console snippets (we read
the saved files instead), grepping bundles for secrets to use, image-optimizer requests toward internal hosts and
DNS rebinding, the remote-code-execution and denial-of-service advisories as tests (kept as version facts only),
cache poisoning, revalidation triggering, runtime matrices.
-->

# Next.js

## When
- Answers carry `/_next/static/`, `__NEXT_DATA__`, `x-nextjs-cache`, `x-middleware-rewrite`, or requests with a
  `Next-Action` header show in `bh-web net`.

## Do
1. Routes from the build, not from guesses: `bh-js <origin>/` reads the bundles; the build manifest
   (`/_next/static/<buildId>/_buildManifest.js`) lists the pages. A route counts once it answers 200 or 403
   live; a 404 is an old build artifact.
2. Props: read `__NEXT_DATA__` (or the streamed RSC payload) of each page as each identity:
   `q -a <identity> -n 4000 <page url>`. Fields the page never shows (another user's object, internal ids,
   admin flags, a token) are the lead. Compare the two identities' props on the same page.
3. Middleware-only authorization: a route that redirects to login when anonymous. One request each, anonymous,
   with `x-middleware-subrequest: middleware`, then `src/middleware`, then
   `middleware:middleware:middleware:middleware:middleware` (CVE-2025-29927; affected versions only, read the
   advisory). The protected page's content in the answer = middleware bypass.
4. Path forms the middleware may match differently from the handler, one each: a trailing slash, a double slash,
   a `.` segment, a duplicated query parameter. A 403 turning into 200 (redirects do not count).
5. Server actions: the `Next-Action` id and body from `bh-web net`; replay the action as the other identity on
   the first identity's object (card `idor`), and anonymous. Actions trust the client more often than routes.
6. Caching: an answer with account data and `x-nextjs-cache: HIT`, or a CDN HIT, is a cache question: skill
   `web-cache`, on a URL of your own only.
7. Version: from the build, the headers or a known file. A version in an advisory's range is a fact for the
   board (skill `false-positive-traps`), never something to exploit.

## Proof
proof.json by lead:
- props: `attack` = the page as the other identity, expecting the first identity's marker in `__NEXT_DATA__`;
  `control` = the same page anonymous, marker absent;
- middleware: `attack` = the protected route anonymous with the `x-middleware-subrequest` header, expecting a
  marker of the protected page; `control` = the same request without the header, expecting the login redirect;
- server action: the card `idor` standard on the action's request.

## Never
- Send a payload from a remote-code-execution or denial-of-service advisory (React Server Components decoding,
  image optimizer): a version fact is the end of it; code run on the server is `bh-note blocked server-exec`.
- Point `/_next/image?url=` at an internal address or a host outside the scope.
- Use a key or secret found in a bundle: what it opens is a question for the operator.

## False positives
- (Strix) A route found in the build that answers 404 live: not deployed.
- (Strix) A redirect is not a bypass: the protected content must be in the answer.
- (Strix) `NEXT_PUBLIC_*` values and placeholders in bundles: public by design.
- (Strix) Props that hold only the viewer's own data, or data the page shows anyway.
- A `__NEXT_DATA__` identical for both identities and anonymous: public page.

## Watch
- App Router and Pages Router may coexist with different checks: the same object through `/api/...` and
  through a server action.
- `x-middleware-rewrite` and 307s with `x-nextjs-redirect` show where the middleware acts: test those routes first.
