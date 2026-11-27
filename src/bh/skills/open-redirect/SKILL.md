---
name: open-redirect
description: Use when a parameter like `redirect`, `next`, `return`, `url`, `to`, `goto` sets where the user is sent, or on login, logout and callback routes.
---
<!-- Source: card src/bh/cards/open-redirect.md (ours), plus the lines FUSIONS.md (skills audit, W3-C) drew from the
Hermes skills bug-bounty/open-redirect-to-ato, redirect-chain-attacks and crlf-injection (no licence stated).
Modified: the external host is the `<payload-host>` token; removed: the source's severity scale ("critical after
login"). -->
# Open redirect

## When
- `redirect`, `next`, `return`, `url`, `to` parameters; login/logout/callback routes.
- Also `goto`, `continue`, `target`, `redir`, `rurl`, `callback`, and the redirect field of a login form (followed
  after login).

## Do
1. Supply an external domain (`https://<payload-host>`) and read the Location header / meta refresh / JS redirect:
   `q -i -n 400 '<url with the parameter>'`. `<payload-host>`: the payload hosts of your scope block; none listed:
   `bh-note blocked other "no payload host declared"`.
2. Try the usual parser confusions only if the first is filtered: `//<payload-host>`, `https:<payload-host>`,
   `/\<payload-host>`, `https://<in-scope host>@<payload-host>`, a backslash form, a full-width colon. One each.
3. CRLF in the parameter (`%0d%0aX-Bhx: 1`): a new header in the answer is header injection; control = the same
   value without the CRLF.
4. Look for a chain: OAuth `redirect_uri`, token in fragment or query sent to the external domain (skills
   `oauth-oidc` and `chaining`).

## Proof
The response sends the browser to an external domain we supplied (Location header, meta refresh or JS). Control:
a benign internal value stays internal. The replay reads status and body, not headers: proof.json attack =
the external value, expecting `<payload-host>` in the body (a meta refresh, a script, or the "Redirecting to" text
most 30x bodies hold); twin control = the same URL with an in-scope path, expecting `<payload-host>` `absent`.
A 30x with an empty body: `bh-note fact "CANDIDATE: open redirect <route>" -s "<the Location line of q -i>"
-e <file>` and look for the chain. `bh-note finding "<title>" --severity <s> --class open-redirect --url <url>
--proof proof.json --summary "<...>" --not-proven "<...>" --counter "<...>" --severity-if "<...>"
--severity-why "<...>"`.

## Never
- Send a real user anywhere: the browser that follows the redirect is ours (`bh-browse`, `bh-web`).
- Point it at a host that is not a declared payload host.

## False positives
- A redirect to a sibling in-scope domain of the same company.
- A redirect that only shows a warning page ("you are leaving") before the external site.

## Watch
- Report alone only if the program pays for open redirects (check the exclusions); otherwise keep it as a fact for
  chaining.
- A redirect never carries the session cookie to the other site: token theft needs a token in the URL or an OAuth
  flow that trusts the redirect.
