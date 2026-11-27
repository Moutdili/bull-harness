---
name: postmessage
description: Use when the app's scripts listen for window messages (addEventListener("message")) or post data to a parent, opener or frame. Reads the origin check and the sink; the DOM is checked before and after.
---
<!--
Source: strix/skills/vulnerabilities/browser_security.md (sections "postMessage and Window Relationships",
"Validation", "False Positives"), Strix (https://github.com/usestrix/strix), Copyright 2025 OmniSecure Inc., Apache
License 2.0.
Also: inputs/skills-audit/FUSIONS.md, section "Classes T41", row "postMessage" (Hermes postmessage-clickjacking, no
licence stated): the three patterns (endsWith origin check, id read from iframe.src instead of the origin, `*` as
target) and the DOM checked before and after.
Modified from Strix (Apache-2.0) by bull-harness: only the postMessage part kept and rewritten into our form; removed:
monkey-patching fetch and listeners in a controlled browser, XS-Leaks timing trials, service-worker and cache
poisoning, worker capabilities, oversized URL and header tests, local-network access, gadget discovery harnesses,
cross-browser matrices.
-->

# postMessage

## When
- The bundles (`bh-js` keeps them in `$BH_DIR/js/`) hold `addEventListener("message"` or `onmessage`,
  or `postMessage(` toward `window.parent`, `window.opener` or a frame.
- The page is framed or opened by another origin by design (widgets, payment or login pop-ups, embeds).

## Do
1. Listeners: `grep -oE 'addEventListener\(.message.[^;]{0,300}' "$BH_DIR"/js/*.js`. For each, read three things
   in the code: the origin check, the message shape, the sink (`innerHTML`, `location`, `eval`, a fetch with the
   session, a storage write, a state change).
2. The check, against the three known weak forms:
   - a string test on `event.origin` (`endsWith`, `indexOf`, `includes`, an unescaped `.` in a regex): an origin
     like `https://<program domain>.<payload-host>` passes;
   - an id or origin read from `iframe.src` or a message field instead of `event.origin`;
   - no check at all.
3. Senders: a `postMessage(<data>, "*")` that carries a token, a code or account data sends it to whoever framed or
   opened the page.
4. DOM before: `bh-browse '<page url>' --as <identity>` and keep the DOM it saves.
5. The test you can run here: a page of the target itself that forwards a value of its URL (query, hash) into a
   message to a frame or to itself. Send a marker through it (`bhx12345`), then the DOM after: the marker in the
   sink the listener writes to. A sink that runs script is an XSS: card `xss`, `bh-browse --xss <marker>`.
6. No relay in the target: the message must come from a page on another origin, which the sandbox never serves.
   Record the code lines and `bh-note blocked other "postMessage: needs a page on a foreign origin: <listener,
   check, sink>"`.

## Proof
proof.json with `"browse"` steps, GET only:
- `attack`: the relay page with the marker (`"browse": {}` expecting the marker in the rendered DOM, or
  `"browse": {"xss": "<marker>"}` expecting `xss CONFIRMED (marker <marker>)`);
- `control`: the same page with a benign value the listener must ignore, expecting the marker (or the
  confirmation line) absent.
A finding from code reading alone is a CANDIDATE fact with the lines quoted, never a finding.

## Never
- Host a page anywhere, or send a link to anyone, to deliver a message.
- Post a message into a chat or a conversation through `bh-web`: messages go through the app's own UI only.
- A message that names another user's id or acts for someone who is not one of your identities.

## False positives
- (Strix) A message reaches the listener but fails its schema, origin, source or state check before any action.
- (Strix) A same-origin check on a window reference the attacker cannot control (randomised names, `noopener`).
- (Strix) Behaviour seen only in one browser build, without the version stated.
- A `*` target on a message that carries nothing private (a height, a "ready" signal).
- A listener with no sink: code that logs or ignores the data.

## Watch
- A strict origin check does not help if the trusted window itself is one the attacker opened (Strix).
- A login or payment pop-up that posts the code to `window.opener` with `*` is an OAuth leak: skill `oauth-oidc`.
- Framing needs the target to allow it: read `X-Frame-Options` and CSP `frame-ancestors` on the listener's page.
