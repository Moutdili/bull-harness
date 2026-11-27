---
name: ssrf
description: Use when a parameter takes a URL or host (`url`, `src`, `webhook`, `callback`) or a feature fetches, imports, previews or renders something server-side.
---
<!-- Source: card src/bh/cards/ssrf.md (ours, W1 S5), plus the line FUSIONS.md (skills audit, W3-C) drew from the
Hermes skills bug-bounty/ssrf-methodology and ssrf-detection-exploitation (no licence stated). Modified: only the
"less obvious sinks" line taken; removed: other writings of internal addresses, internal port sweeps, non-HTTP
schemes, third-party callback services. -->
# Server-side request forgery

## When
- Parameters that take a URL or host (`url`, `src`, `webhook`, `callback`, image/PDF/preview features).
- Less obvious sinks: PDF or screenshot generators (an image or frame in the HTML they render), media importers
  that follow playlists, webhooks, "import from URL".

## Do
1. Feed an in-scope URL you control the content of (an in-scope page, not a third party) and see if the server
   fetches it: the content of that page read and returned or rendered by the server is the proof; error messages
   that name the fetch are a lead.
2. Redirect-based variants only through in-scope redirectors, toward an in-scope page.
3. Blind (nothing read back): look at the scope block of your task.
   - It shows a `support (oob): <oob host>` line: `bh-note canary`, then aim the parameter once at
     `https://<oob host>/c/<canary>`, exactly that: one call, never any other data in the URL (no path of the
     target, no query, no name or value read from it). Send that request as one identity, the one you will name
     `--victim`; the other identity never sends the canary. The host reads the listener, you cannot: the gate
     refuses that host to every client of the sandbox, and such a refusal proves nothing.
   - No `support (oob)` line: there is no out-of-band listener; `bh-note blocked oob-needed` (Proof below).
4. Record the sink either way: `bh-note cover "<METHOD /route>" ssrf clean|suspect -e <raw body path>`.

## Proof
Either the content of an in-scope page the server read and returned or rendered (step 1), or a request
received on a host of ours that the scope declares as a listener (step 3: the host reads it). proof.json for
step 1: attack = the parameter set to the in-scope page, expecting a marker only that page holds; twin control =
the same request with the parameter set to another in-scope page without the marker, expecting it `absent`.
`bh-note finding "<title>" --severity <s> --class ssrf --url <url> --proof proof.json --summary "<...>"
--not-proven "<...>" --counter "<...>" --severity-if "<...>" --severity-why "<...>"`.
Step 3, when the scope block shows a `support (oob)` host: control = the same request with the parameter set to an
in-scope page instead of the callback, N runs (no callback, 0/N); then `bh-note finding "<title>" --severity <s>
--class ssrf --url <url> --observation <canary> --victim <the identity that sent it> --attacker <the other>
--control 0/N --summary "<the parameter, the one call, UTC time>" -e <file with the exact request>`. The host
decides from what its listener received, never from what you say.
No `support (oob)` host in the scope block and nothing rendered back: `bh-note blocked oob-needed "<url and
parameter>" --tried "<...>" --would-prove "<...>"`.

## Never
- Aim the server at a loopback, link-local, cloud metadata or internal address or name, in any spelling (decimal,
  hex, IPv6, a DNS name that resolves to one, a redirect to one): the program forbids it and it proves nothing here.
- Scan internal ranges, hit third-party hosts through the target.
- Use a scheme other than `https` or `http`.
- Put anything but the canary in a callback URL, call it more than once per sink, or aim a callback at any host
  but the scope's `support (oob)` one (never a public collaborator or a third-party catcher).

## False positives
- Your own client fetched it, not the server: a row in `bh-web net` or `bh-browse` output is the browser's request.
- A preview built in the browser from data the page already holds is client-side.
- An error that names the URL without fetching it (validation only).

## Watch
- An abnormal answer: first one variant that keeps the syntax (the same scheme and host, a different in-scope
  path), then two close witnesses at most (another in-scope page, the parameter empty), before you widen anything.
- An assistant with tools is also a request sender (skill `ai-connectors`); the same proof applies.
- XML or SVG imports that fetch external entities: skill `xxe`.
