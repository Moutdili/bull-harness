---
name: graphql
description: Use when the target exposes a GraphQL endpoint (`/graphql`, `/gql`, `/graphiql`) or its JS sends `query`/`mutation` documents.
---
<!-- Source: card src/bh/cards/graphql.md (ours); strix/skills/protocols/graphql.md (Strix, Apache-2.0); the lines
FUSIONS.md (skills audit, W3-C) drew from the Hermes skills bug-bounty/graphql-error-enumeration and
bug-bounty/graphql-injection (no licence stated). Modified: condensed and rewritten for two identities of ours;
removed from Strix: alias enumeration of ids, array batching to pass limits, fragment bombs and other complexity
tests, filter evasion, transport and timing tricks to pass limits, persisted-query hash guessing. -->
# GraphQL

## When
- `/graphql`, `/gql`, `/graphiql` endpoints, or a client bundle that sends `{"query": ...}` (`bh-js` lists them).
- Transports: POST with `application/json` or `application/graphql`, GET with `?query=`, websocket subscriptions,
  multipart uploads.

## Do
1. One introspection query; if disabled, read operation names from JS (`bh-crawl`, `bh-js` output) instead.
   Introspection may be refused on POST and answered on GET (`?query={__typename}`), or for one type
   (`__type(name:"User")`). Refused everywhere: skill `graphql-schema-from-errors`.
2. Map the schema once: root operations, types, interfaces and unions, directives, custom scalars. Mark the
   sensitive fields (email, tokens, roles, billing, file URLs, admin flags):
   `bh-note fact "graphql schema" -s "<operations taking ids; sensitive fields>" -k recon`.
3. List queries and mutations that take ids or user references: test them with the skill `idor` (two identities).
   In one request, aliases compare our two objects: `own: order(id:"<attacker's id>") {id}` and
   `other: order(id:"<victim's id>") {id}`, nothing else.
4. Field-level authorization: a field reachable through another type that the direct query refuses; a child field
   (`user(id:"<victim's id>") { privateData }`) whose resolver trusts the parent's check.
5. Relay `node(id:)`: decode the Base64 global id of the victim's object, keep its type, query it as the attacker.
   Connections: a cursor decoded and changed must not cross the owner boundary (our objects only).
6. Mutations: extra input fields passed to the backend (skill `mass-assignment`), partial updates that skip
   validation, `{"id": 1}` vs `{"id": "1"}` vs `{"id": [1]}` (skill `type-confusion`), on our own objects.
7. Arguments named `filter`, `where`, `order` reach a query: test them with the skill `sqli` and the skill
   `nosql-injection`.
8. Federation: `query { _service { sdl } }` once; `_entities` with a representation of the victim's object, as
   the attacker. Directives: `@defer`/`@stream` returning a gated field the plain query refuses; custom `@auth`
   directives checked on each resolver path.
9. Parity: the same operation over GET, POST and the websocket (skill `websocket-origin`) answers with the same
   authorization; a persisted-query hash from the bundle replayed with the attacker's variables.
10. Batching and aliases only to compare authorization, never to multiply requests.

## Proof
Unauthorized data or a mutation reached through GraphQL; the IDOR and auth standards apply. proof.json: setup as
the victim (the query on its own object, expecting its marker), attack the same POST as the attacker expecting
that marker, twin control the same POST without a session (or the same body with the attacker's own id) expecting
it `absent`. Keep the exact selection set and variables. `bh-note finding "<title>" --severity <s> --class graphql
--url <endpoint> --proof proof.json --summary "<operation, field, who read whose>" --not-proven "<...>" --counter
"<...>" --severity-if "<...>" --severity-why "<...>"`.

## Never
- Deep nested queries, fragment cycles or large batches (denial of service), mutations on objects you do not own.
- Aliases or batches over ids you do not own: two objects, ours, per request.
- Subscriptions to channels or filters that name another user's id.

## False positives
- Introspection alone is information.
- Field suggestions ("Did you mean") and an exposed GraphiQL page are information.
- An error object inside a 200 (`"errors": [...]`, `data: null`) is a refusal, not access.

## Watch
- An "unknown field" error and an "unauthorized field" error that differ reveal that the field exists.
- A gateway that checks authorization while a subgraph does not: `_entities` is where it shows.
- GET queries with cookie sessions make mutations reachable cross-site: skill `csrf`. A cache in front without
  `Vary` on the session: skill `web-cache`.
