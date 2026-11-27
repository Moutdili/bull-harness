---
name: websocket-origin
description: Use when the app opens a websocket that carries account data and the scope allows websockets. Checks whether the handshake accepts a foreign Origin with a cookie session (cross-site hijacking).
---
<!--
Source: hermes/bug-bounty/websocket-hacking/SKILL.md (no author or licence stated; it points to PortSwigger Web Security Academy, the OWASP HTML5 cheat sheet and HackTricks).
Modified: translated; bound to the gate's websocket rules; hosted PoC pages, message injection against other users, XSS-based socket theft, a proxy man-in-the-middle and denial of service removed.
Role: hunter. No class id exists yet (see out/README.md).
modified (bull-harness W3-H): payload host `<marker>.<payload-host>` in step 3; the unmeasured line on `q` and a
101 answer removed (not measured); "chat behind a human challenge" named as a chat through bh-browser; class
standard now in classes_more.json.
-->

# Websocket handshake origin

## When
- `bh-web net` or a `bh-browse` summary shows a websocket to a target ("websockets: N opened to the target").
- The scope has `websockets: true`. Without it the gate refuses every websocket: nothing to test.
- NOT on a program whose chat goes through bh-browser (behind a human challenge): there the handshake belongs
  to the browser alone, and a message sent by any other path than `bh-web` is forbidden. Read frames with
  `bh-web frames`, never open a socket yourself.

## Do
1. How does the socket authenticate? Read the handshake in `bh-web net --last 200`: a cookie only, or a token
   in the query string, a header, or the first message. A token that a page of another site cannot know =
   no cross-site hijacking: `bh-note fact "<ws url>: token-authenticated" -k dead-end`.
2. Cookie only: read the session cookie's `SameSite`. `Strict` or `Lax` = the browser will not send it on a
   cross-site handshake: dead end, record it.
3. One handshake with a foreign origin, as user-a:
   `q -a user-a -i -n 200 -H 'Origin: https://<marker>.<payload-host>' -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: <16 random bytes, base64>' <https form of the ws url>`
   (`<payload-host>`: the payload hosts of your scope block; none listed in your scope block:
   `bh-note blocked other "no payload host declared"`.)
   - `101 Switching Protocols`: the origin is not checked.
   - 400, 403: checked.
4. One more, only if 101: the same with no `Origin` header, and with `Origin: null`.
5. What crosses the socket without a per-message secret: read your own traffic with `bh-web frames --last 30`.
   Account data arriving unprompted, or actions accepted as plain messages, is what gives the impact.

## Proof
- `attack`: the handshake of step 3 as user-a, expecting 101;
- `control`: the same handshake with `"as": null`, expecting a refusal or a socket that gets no account data.
- Evidence file: the cookie line (`SameSite`), and the frames that show what the socket delivers.
- `--not-proven`: "no cross-site page opened the socket; no message was sent from the foreign origin".

## Never
- Send messages on a socket you opened by hand on a chat product, or to act for another user.
- More than the gate allows: 2 sockets, a few messages a minute. A refusal ends the test.
- Any message that names another user's id.

## False positives
- A 101 alone. Without cookie authentication and data on the socket there is nothing to steal.
- Missing CORS headers: websockets are not subject to CORS; only the `Origin` check counts.
- Frameworks that authenticate in the first message (a token in a connect packet): the handshake is open on
  purpose.

## Watch
- Socket.IO style endpoints answer the handshake with a session id and expect a connect packet next: an empty
  connect accepted with account data behind it is the same finding one step later.
- Websocket handshakes are invisible to the id-enumeration guard and frames are not scope-checked: stay on
  your own objects.
