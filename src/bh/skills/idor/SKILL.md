---
name: idor
description: Use when a route, body or query carries an object id (`/{id}`, `user_id`, `order`, `uuid`) and two of our identities can each own such an object.
---
<!-- Source: card src/bh/cards/idor.md (ours), plus the lines FUSIONS.md (skills audit, W3-C) drew from the Hermes
skills bug-bounty/idor-hunting-methodology, bug-bounty/idor-methodology and bug-bounty/bug-bounty-proof-package (no
licence stated). Modified: rewritten for this harness, roles left free (victim and attacker are either of our
identities); removed: loops over ids, id fuzzing, any read of an object that is not ours. -->
# IDOR / BOLA

## When
- Routes or parameters carry object ids (`/{id}`, `user_id`, `order`, `uuid`), and you have two identities.
- `bh-note frontier` lists identities with objects of their own (one of ours is the victim, the other the attacker).

## Do
1. First pass, after mapping and with 2+ identities: `bh-authz`. Every known endpoint is replayed as each identity
   and anonymous; it flags owner data seen by another identity (horizontal). It leaves `raw/authz-*/proof.json`
   for the best candidate: read the raw answers before you use it.
2. As the victim, create or find the victim's own objects; note their ids from your own responses (never enumerate).
3. As the attacker, do the same. You now hold one object per identity.
4. `qq <url with the victim's id>`: one line per identity and anonymous (status, size, hash). Then replay the
   attacker's read of its own object with the victim's id: `q -a <attacker> -n 2000 <url with the victim's id>`.
5. Every verb the route supports, on objects we own: GET, then PUT/PATCH/DELETE on the victim's test object only.
   Same route, another method: a GET that is refused may be accepted as POST, PUT or PATCH (on our own objects only).
6. Try the id in other places: JSON body, query string, GraphQL variables, nested routes (`/orders/{id}/items`),
   an array form (`id[]=<a>&id[]=<b>`, `id=<a>,<b>`), a sibling parameter name (`userId`, `user[id]`, `uid`,
   `account_id`), an identity header the server may read (`X-User-ID`). `<a>` and `<b>` are our two objects.
7. A collection that answers 403 says nothing about its items: request one item of the victim's as the attacker.
8. Each route tried: `bh-note cover "<METHOD /route>" idor clean|suspect -e <the raw body path q printed>`.

## Proof
The least intrusive proof is a read. proof.json, three steps on the same method and URL:
- setup `"as": "<victim>"` expecting the victim's marker (`{"status": [200], "contains": ["<marker>"]}`);
- attack `"as": "<attacker>"` expecting the same marker;
- twin control `"as": null` (no session) on the same URL, expecting `{"status": [401, 403, 404]}`.
A write: the attack changes the victim's test object, a later setup step as the victim reads the change back; the
control is the same write without a session. Then:
`bh-note finding "<title>" --severity <s> --class idor --url <url> --proof proof.json --summary "<who read what>"
--not-proven "<...>" --counter "<...>" --severity-if "<...>" --severity-why "<...>"` (skill `report-writing`).
A canary seen on the attacker's side proves nothing unless it was planted where only the victim can read it.

## Never
- Read an object that is not one of our identities' (seen once: stop, `bh-note blocked third-party-data "<route,
  no content>"`), or write to any object that is not the victim's test object.
- Enumerate, guess or increment ids, or loop over ids, even to show that no limit exists.
- Keep a write's effect: undo it as the victim.

## False positives
- An empty 200, an OPTIONS or preflight answer, an error page inside a 200, or public data is not access.
- The same answer for everyone (a public profile, a product page): compare with anonymous.
- An id the attacker received legitimately (shared, invited) opening what it was shared for.

## Watch
- Numeric vs UUID ids, ids leaked in other responses (lists, emails, exports), tenant/org ids (skill `multi-tenant`).
- Encoded ids (Base64: decode, change, re-encode; the `sub` of a JWT); an endpoint that returns the encrypted form
  of any value you submit is an oracle for the victim's encrypted id.
- A different Content-Length between your object and the other's is the first signal; then read the body.
- A write that takes extra fields (`owner_id`, `role`): skill `mass-assignment`. A role boundary rather than an
  owner boundary: skill `broken-access-control`.
