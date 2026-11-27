---
name: cors
description: Use when an authenticated JSON API, especially one behind a cookie session, may answer cross-origin reads (`Access-Control-Allow-Origin`, JSONP callbacks).
---
<!-- Source: card src/bh/cards/cors.md (ours), plus the lines FUSIONS.md (skills audit, W3-C) drew from the Hermes
skills bug-bounty/cors-misconfiguration-exploitation and bug-bounty/jsonp-attacks (no licence stated). Modified:
rewritten for this harness; nothing removed beyond what the card already forbade. -->
# CORS

## When
- Authenticated JSON APIs, especially behind cookie sessions.
- An endpoint that takes a `callback` or `jsonp` parameter.

## Do
1. Send the authenticated request with `Origin: https://<payload-host>` and read `Access-Control-Allow-Origin` and
   `Access-Control-Allow-Credentials`: `q -a <identity> -i -H 'Origin: https://<payload-host>' <url>`.
2. If reflected with credentials, check that the response holds sensitive data of the identity.
3. Three more conditions before it is exploitable: the preflight of a non-simple request is accepted (send the
   OPTIONS); `Access-Control-Allow-Credentials: true` is present; the session cookie is `SameSite=None`. An API that
   takes only an `Authorization` header cannot be read cross-site without another bug.
4. One condition missing: record a fact, not a finding (`bh-note fact "<route>: CORS reflects, <missing>" -k recon`).
5. Variants only if the first is refused: `null` origin, a lookalike subdomain of an in-scope domain.
6. JSONP: an authenticated endpoint that wraps the identity's data in a callback (`?callback=bhx12345`) is readable
   cross-site whatever CORS says; control without session.
`<payload-host>`: the payload hosts of your scope block; none listed: `bh-note blocked other "no payload host declared"`.

## Proof
A credentialed cross-origin read: Access-Control-Allow-Origin reflects an arbitrary origin AND
Access-Control-Allow-Credentials is true, on an authenticated response that holds sensitive data. The replay reads
status and body, not headers: proof.json attack = `"as": "<identity>"` with the header `Origin:
https://<payload-host>`, expecting the identity's marker; twin control = the same request `"as": null`, expecting it
`absent`. Quote the two response headers of `q -i` in `--summary`. JSONP: the attack expects `bhx12345(` and the
identity's marker, the control without session expects the marker `absent`. `bh-note finding "<title>" --severity
<s> --class cors --url <url> --proof proof.json --summary "<...>" --not-proven "<...>" --counter "<...>"
--severity-if "<...>" --severity-why "<...>"`.

## Never
- Host a page that reads a real user's data: the proof stays between our identity and the gate.
- An origin that is not a declared payload host or an in-scope lookalike.

## False positives
- Report only the credentialed read of sensitive data; a wildcard on public data is not a finding.
- `Access-Control-Allow-Origin: *` with credentials: browsers refuse that pair.
- A reflected origin on an endpoint whose answer holds nothing of the identity.

## Watch
- A reflected origin only for in-scope subdomains turns into a finding only with an XSS on one of them (skill
  `chaining`).
- `Vary: Origin` missing on a cached answer: skill `web-cache`.
