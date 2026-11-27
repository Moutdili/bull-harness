---
name: web-cache
description: Use when answers carry cache headers (X-Cache, CF-Cache-Status, Age) on pages that hold account data or reflect a header. Cache deception and poisoning, tested only on a cache key of your own.
---
<!--
Source: hermes/bug-bounty/web-cache-deception-attack/SKILL.md; merged from hermes/bug-bounty/web-cache-attacks and hermes/bug-bounty/host-header-attacks (no author or licence stated; the sources point to PortSwigger Web Security Academy, OWASP WSTG and PayloadsAllTheThings).
Modified: translated; every test bound to a unique cache key; the keyed-buster check, the stop rule and the twin control are ours; extension loops and "victim visits the link" steps removed.
Role: hunter. The plan (T41) asks for this class; its proof standard is still to add in `classes.py`.
modified (bull-harness W3-H): payload host `<marker>.<payload-host>` in poisoning step 2; class standard now in
classes_more.json.
-->

# Web cache: deception and poisoning

## When
- A CDN or reverse proxy caches (`X-Cache`, `CF-Cache-Status`, `Age` in answers).
- Deception: a page of your own account (profile, settings, API "me").
- Poisoning: an answer that reflects a request header or an ignored parameter.

## Do: deception (your private page stored as a public file)
1. Marker: something only user-a's page holds (a display name you set to `bhx` and 5 digits).
2. As user-a, request the page under a static-looking name nobody else will ever ask for:
   `q -a user-a -i -n 400 '<origin>/account/bhx12345.css'`. The page still shows your data and a cache header
   says stored or, on a second request, HIT: candidate.
3. Variants, one each, only if step 2 served a 404 or no cache header: `/account;bhx12345.css`,
   `/account%2Fbhx12345.css`, `/account/bhx12345.css%3Fx`, another extension (`.js`, `.ico`, `.png`).
4. The test that matters: the same URL with no session, `q -i -n 400 '<same url>'`. Your marker in the
   anonymous answer = the cache serves your private page to anyone.
5. Twin control: a sibling URL you never requested while logged in (`.../bhx54321.css`), anonymous. It must
   not hold the marker.

## Do: poisoning (a header changes what everybody gets)
1. First prove your buster is part of the cache key: `/?cb=bhxA` and `/?cb=bhxB` must each go MISS then HIT on
   their own. If the query string is not keyed, STOP: any test would poison the real page.
   `bh-note blocked other "cache ignores the query string on <path>: no safe poisoning test"`.
2. On your buster only: `q -i -n 600 -H 'X-Forwarded-Host: <marker>.<payload-host>' '<origin>/?cb=bhxA'`. Is
   the value reflected (a link, a script URL, a redirect)? (`<payload-host>`: the payload hosts of your scope
   block; none listed in your scope block: `bh-note blocked other "no payload host declared"`.)
3. Same URL without the header. Still reflected and HIT = the poisoned answer is cached, for your key.
4. Other inputs, one each: `X-Forwarded-Scheme`, `X-Host`, `X-Forwarded-Server`, `Forwarded: host=...`, a body
   sent with a GET. The gate refuses a forged `Host` header: do not try it.

## Proof
- Deception: proof.json with `setup` as user-a on the URL (expects the marker), `attack` with `"as": null`
  on the same URL (expects the marker), `control` with `"as": null` on the sibling URL (marker absent).
- Poisoning: `attack` = the buster URL without the header, expecting the reflected value after the setup
  step sent it; `control` = another buster, value absent.
- In `--not-proven`: the cache lifetime you saw, and that no page other users request was touched.

## Never
- Poison or store anything under a URL real users request. Always a unique name or a unique, keyed buster.
- Use a page with more personal data than the marker needs: the entry stays public until it expires.
- Loop over extensions or headers. A handful of single requests.

## False positives
- A HIT on an answer that holds no private data, or on the login page.
- `Cache-Control: private` or `no-store` with a MISS every time.
- A header reflected but never cached (step 3 fails): no impact on anyone.
- The marker visible only because your cookie was still sent.

## Watch
- Note the time and the cache lifetime; ask in the finding for the entry to be purged if it is long.
- Password-reset links built from `X-Forwarded-Host` are the same root cause seen in a mail: ask a reset for
  your own identity with the header set, then `bh-mail <identity>` shows whether the link names your payload
  host (a link outside the scope prints as `[link: <host>]`). Supporting data only: the finding keeps its
  proof.json or its observation. `mail UNAVAILABLE` → `bh-note blocked other "<what to read in which mailbox>"`,
  as before.
