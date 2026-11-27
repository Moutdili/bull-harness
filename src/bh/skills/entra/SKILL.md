---
name: entra
description: Use when an in-scope API signs its users in with Microsoft Entra or a Microsoft account and two of our identities hold their own tokens for it.
---
<!--
Source: strix/skills/protocols/oauth.md (sections "Scope and Token Issues", "OpenID Connect Specific", "Validation",
"False Positives"); strix/skills/cloud/azure.md (the identity parts only: "Scope and Identity Baseline", the token
audience lines of "Conditional Access and Authentication", "Applications, Service Principals, and Workload Identity"
for the delegated versus application permission line, "Common False Positives"). Strix
(https://github.com/usestrix/strix), Copyright 2025 OmniSecure Inc., Apache License 2.0.
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form, on the target's side only: the token of one
of our identities, presented to the target's API, and what that API accepts (audience, scope, account). The login
hosts stay support hosts, never targets. Removed: redirect_uri matrices, client enumeration from bundles and public
repositories, dynamic registration, device-code polling, Referer harvesting, account linking from an attacker's
provider, every Azure resource, role, privileged identity, conditional access, storage, key vault and managed
identity test, the command-line tools and the audit tool of the source, directory-wide inventory, "Tooling",
"Pro Tips", "Summary".
-->

# Microsoft Entra and Microsoft accounts, from the target's side

## When
An API of your scope accepts a bearer issued by Microsoft (Entra or a personal Microsoft account), and two of our
identities each hold their own, which the gate injects with `q -a <identity>`.
What is tested is the target's API: which token it accepts, for which audience, scope and account. The sign-in hosts
themselves (`login.microsoftonline.com`, `login.live.com`) are support hosts of the scope: never tested (see Never).
Not this skill: our own OAuth flow on an authorization server of the scope (skill `oauth-oidc`), a token's signature
and claims (skill `jwt`).

## Do
1. Map, 5 turns at most: as each identity, `bh-web net --last 100`: the API hosts the app calls (a host outside your
   scope block: `bh-note blocked other "<host>"`). On each API route seen, `qq <url>`: 200 under each identity and
   401 anonymous = a route bound to an identity token. `bh-note fact "<api>: token-bound routes" -k recon`.
2. Tokens belong to the browser and the gate: their values are redacted in everything you read, and you never type,
   copy or decode one. What you test is what the target's API does with the token of each identity.
3. One question per surface, in this order:
   a. The other account's token: the attacker's own valid token on a route that names the victim's object (an id
      seen in the victim's own traffic). The API must bind the object to the token's account, not only accept it.
   b. The grant's scope: an object the victim shared with the attacker read-only; the attacker's token on its write
      route (rename, change, delete), one request. The API must check the grant, not only the token.
   c. Revocation: the victim revokes that share; the attacker's token on the object, 3 times over 2 minutes.
   d. A token-bound route answering anonymously, or with cookies only where the interface sends a token.
4. Each test is one request per identity: `qq <url>` first (each identity and anonymous on one line), then
   `q -a <attacker> -n 2000 <url>` when the attacker gets 200.
5. Twin control for each question: the same request as the victim on its own object (it must answer as designed),
   and the same request anonymous (it must be refused).
6. A write: one `q -a <attacker> -X <method> <url>` per route, on a test object the victim created for it; the
   victim re-reads it, then undoes it.
Next: `bh-note intent "<api>: question <a-d>, victim <identity>, attacker <the other>"`, then step 4.

## Proof
proof.json: setup `"as": "<victim>"` reading its own object (the marker in it), attack `"as": "<attacker>"` on the
same URL expecting `{"status": [200], "contains": ["<marker>"]}`, twin control `"as": null` on the same URL
expecting `{"status": [401, 403, 404]}`. `bh-note finding "<title>" --severity <s> --class
idor --url <url> --proof proof.json --summary "<whose token, which grant, what it reached, k/N>"
--not-proven "<...>" --counter "<...>" --severity-if "<...>" --severity-why "<...>"`. A token-bound
route that needs no token at all (question d): `--class auth`, and say so in `--summary`.
The report names the identities and the routes, never a token value.

## Never
Test, probe or send a form to `login.microsoftonline.com`, `login.live.com` or any sign-in host: they are support
hosts, never targets, and the gate refuses your GETs outside their declared paths. Request a token yourself (no
device code, no password grant, no client credentials), register an application, or consent for anyone. A tenant
that is not ours, a directory query, another user's token. Put a token in a note, a fact or a report. Guess or
enumerate ids, tenants or client ids. A host outside your scope block: `bh-note blocked other "<host>"`.

## False positives
- The resource checks the token's account and grant: 401, 403 or 404 on the other's object is isolation (Strix).
- The attacker reading its own object with its own token; a 200 that is a sign-in page or an empty list.
- A role or permission a token names but the API never relies on: not a flaw by itself (Strix).
- A refusal `identity bearer expired`: the gate's own answer, neither the target's nor a control.

## Watch
On personal Microsoft accounts there is no tenant of ours: questions about directory roles, consent or tenants do not
apply; record `bh-note fact "<api>: no tenant (personal accounts)" -k dead-end --why environment` once.
A 401 under an identity is a refusal of access, not a dead session (the gate decides a session is dead).
`me` in a route is always the caller: a cross-account test needs a route that names the other account's object.
Audience and scope are set by the sign-in, never by you: you show their effect (a, b, c), not a crafted token. A
token of one API accepted by another cannot be shown with our tools: `bh-note fact "<api>: audience not testable" -k
think` at most, never a finding.
