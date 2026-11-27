---
name: api-surface-mapping
description: Use when `bh-crawl` left a single-page app's API thin, or an API answers "missing header" or type errors. Reads CSP, bundles and error messages to rebuild routes, required headers and field types.
---
<!--
Source: hermes/bug-bounty/api-hacking-methodology/SKILL.md; merged from hermes/bug-bounty/api-hacking, hermes/bug-bounty/recon-methodology, hermes/arsenal-cavaliers and section titles of hermes/security/bug-bounty-methodology (no author or licence stated).
Modified: translated; real programs, session tokens and user data from case studies removed; endpoint brute force, mobile APIs, company and people OSINT and login-host probing removed.
Role: hunter. Mapping only: everything found here is a fact, not a finding.
modified (bull-harness W3-H): the anti-bot wall of step 2 answered by `bh-web wait-human` when the program has
bh-browser; a Proof section added (the common form asks for one).
-->

# API surface mapping

## When
- After `bh-crawl`, the board lists few API routes for an app that clearly calls many.
- An API refuses you with a message about a missing header, a version, or an invalid JSON type.

## Do
1. CSP first, one request: `q -i -n 0 <origin>/` and read `content-security-policy`. `connect-src` names the
   API hosts, the storage buckets, the backend-as-a-service project and the payment provider; `report-uri`
   names one more endpoint. Only hosts in scope are targets: the gate decides.
2. Response headers as a stack signature: `server`, `via`, `x-powered-by`, `x-generator`, `server-timing`,
   session cookie names. A challenge header from the edge (`cf-mitigated: challenge`) means an anti-bot wall:
   never work around it. Without bh-browser on this program: `bh-note blocked captcha "<host>"`. With
   bh-browser: `bh-web wait-human` (the operator passes it; skill `bh-web-manual`), never `blocked captcha`.
3. Bundles: the crawl saved them (path shown in its summary). Grep by framework:
   - generic: `grep -oP '"/api/[a-zA-Z0-9_/.-]+"'` and `grep -oP '"(/v[0-9]/[a-zA-Z0-9_/.-]+)"'`
   - fetch/axios: `grep -oP '(fetch|axios|get|post|put|delete)\s*\(\s*["`/][^"`]*/api/[^"`]*'`
   - Vue: `grep -oP '\$http\.(get|post|put|delete)\s*\(["`/][^"`]*'`
   - Angular: `grep -oP 'this\.http(Client)?\.(get|post|put|delete)\s*<[^>]*>\s*\(["`/][^"`]*'`
   - Ember Data: `grep -oP 'createRecord\("[^"]+"|findAll\("[^"]+"|query\("[^"]+"'` (model `space` means
     `/api/spaces`: names are pluralised).
4. Server-rendered pages: look in the HTML for a preloaded state object (`__PRELOADED_STATE__`, an Apollo
   state): it can name the GraphQL endpoint and its types. On Firebase Hosting, `/__/firebase/init.json`
   gives the project's public config. Both are public by design: mapping, not findings.
5. Required custom headers: an answer like "missing version header" names what the bundle sets. Find the
   header name in the bundle (`grep -oP 'X-[A-Za-z-]+'`) and send it with `q -H`.
6. Sibling versions, one request each on a route you already know: `/v0/`, `/v2/`, `/v1-beta/`. A 403 or 422
   that names a scope or a parameter proves the route exists.
7. Typed backends: when a JSON body is refused as invalid, send `{}` first, then one field at a time. An
   "invalid JSON" error on one field means its type is wrong (an enum may want a number); a "missing
   parameter" error means types passed and business validation started.
8. Record the map: `bh-note fact "<origin> api map" -s "<METHOD route> ..." -k recon`, then work the untested
   list of the board.

## Proof
None here: the map is facts (`-k recon`). A route becomes a lead after one live request, and a finding only
with the proof of its class (skill `proof-package`: the attack and its twin control).

## Never
- Guess routes from a wordlist here; this skill reads what the app already ships.
- Use a session token copied from a browser or a file: sessions come from the gate (`q -a <identity>`).
- Look up people, staff addresses or accounts on a login host: none of it is a target.

## False positives
- A 200 HTML answer on an API path is the app shell (same size on every path).
- A `204` on a write is not a success until a read shows the change.
- A staging or internal host name in a bundle is out of scope unless the gate lets it through.
- Publishable keys and public config are public.

## Watch
- Routes in a bundle may belong to another client version: confirm each with one live request before
  planning tests on it.
- New or recently changed routes first: they are where the next finding is least likely to be a duplicate.
