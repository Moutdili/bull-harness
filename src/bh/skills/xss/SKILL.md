---
name: xss
description: Use when a parameter is reflected in HTML or JS, or content one identity stores (comment, profile, feedback) is shown to the other.
---
<!-- Source: card src/bh/cards/xss.md (ours), plus the lines FUSIONS.md (skills audit, W3-C) drew from the Hermes
skills bug-bounty/airbnb-xss-json-smuggling, bug-bounty/emoji-unicode-xss and bug-bounty/css-injection (no licence
stated). Modified: roles left free, the payload host is the `<payload-host>` token; removed: filter and firewall
evasion lists, blind payloads left where third parties render them. -->
# Cross-site scripting

## When
- Parameters reflected in HTML or JS, stored user content (comments, profile, feedback).
- Client-side routes (`/#/...`) and DOM sinks that read the URL, `postMessage` or storage (skill `postmessage`).

## Do
1. Send a unique marker (`bhx12345`) and find EVERY place it comes back (response, other pages, the other
   identity's view of your own content). Note the context: HTML text, attribute, script, URL.
2. Pick the payload for that context only, and check whether it comes back unencoded.
3. Execution in a real browser: `bh-browse '<url with payload>' --xss <marker>` with a payload that calls
   `alert('<marker>')` or sets `window.__bhxss='<marker>'`. Only `xss CONFIRMED (marker ...)` is proof.
4. Stored: inject only into objects one of our identities owns, and view them as the other one
   (`bh-browse '<url>' --as <reader> --xss <marker>`).
5. `<payload-host>`: the payload hosts of your scope block; none listed: `bh-note blocked other "no payload host declared"`.

## Proof
The payload reaches an executable context unencoded and executes. proof.json, GET only: the attack step holds
`"browse": {"xss": "<marker>"}` and expects `{"contains": ["xss CONFIRMED (marker <marker>)"]}`; its twin control
is the same route with a benign value, expecting `{"absent": ["xss CONFIRMED"]}`. A marker in the URL is swapped
for a fresh one at replay; a stored one stays "hunter-chosen" (say so in `--not-proven`).
`bh-note finding "<title>" --severity <s> --class xss --url <url> --proof proof.json --summary "<...>"
--not-proven "<...>" --counter "<...>" --severity-if "<...>" --severity-why "<...>"`.

## Never
- Store a payload where real users will see it (public pages, support tickets).
- Use payloads that call out to third parties, steal a session value or do more than set the marker.
- A payload loop: one page, one marker per `bh-browse`.

## False positives
- Reflection alone, or a payload that is HTML-encoded, is not XSS.
- A dialog from another origin (an ad frame, a widget): only the step's own origin confirms.
- Self-XSS (only you can put the payload in your own view) pays only in a chain (skill `chaining`).

## Watch
- An abnormal answer: first one variant that keeps the syntax (the same quote closed, the same tag balanced), then
  two close witnesses at most (a neighbouring value, the request without the payload), before you widen anything.
- A value reflected inside `<script type="application/json">`: `</script>` ends the block whatever the JSON quoting.
- A filter applied before a charset conversion: a character the conversion turns into `<` passes the filter
  (rare; one marker test).
- Only style can be injected: an attribute selector with a background URL reads a value of the page; point it at
  `https://<marker>.<payload-host>/`, outside the scope, as in the skill `ai-output-rendering` (the gate refuses
  it and the attempt is logged).
- Client-side template or prototype tricks: skills `ssti` and `prototype-pollution`.
