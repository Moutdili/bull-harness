---
name: broken-access-control
description: Use when identities differ by role (`admin`, `member`, `guest`) or tenant (`@A`, `@B`) and admin, settings, export, invitation, billing or tenant routes exist.
---
<!-- Source: card src/bh/cards/broken-access-control.md (ours), plus the lines FUSIONS.md (skills audit, W3-C) drew
from the Hermes skills review-nemesis, .archive/supabase-postgrest-audit, bug-bounty/api-hacking and
.archive/differential-http-parsing (no licence stated). Modified: rewritten for this harness; nothing removed beyond
what the card already forbade. -->
# Broken access control (vertical, cross-tenant, function level)

## When
- The program gives identities with different roles (`admin`, `member`, `guest`) or tenants (`@A`, `@B`): see
  `BH_IDENTITY_ROLES` in the identities line. Admin routes, settings, exports, invitations, billing, tenant switches.

## Do
1. Map as the most privileged identity first, so its admin and settings routes land in the surface.
2. Run `bh-authz` (owner = the privileged identity): every route is replayed as each other identity and anonymous.
   `[vertical]`: a lower role got what only the higher role gets. `[horizontal]`: another tenant got this tenant's
   data. It leaves `raw/authz-*/proof.json` for the best candidate.
3. For each candidate, read the raw answers: the protected data (owner marker, admin-only field) must be in the
   lower identity's answer, not a public shell. Then use the `proof.json` it wrote (attack: lower identity,
   control: no session or a third identity).
4. Function level: actions the lower role must not trigger (invite, change role, export), only on objects of our
   own identities; the owner re-reads the object to see the effect. The same route under a sibling API version
   (`/v0/`, `/v1-beta/`) or another method may skip the role check. More: skill `function-level-authz`.
5. Cross-tenant: an object id of tenant A requested as tenant B, in the path, body, query, or a tenant header
   (skill `multi-tenant`).

## Proof
A lower-privileged identity (or no session) reads or performs what only a higher role, or only the object's owner
or tenant, may: the answer holds that role's or owner's data, or the action takes effect. Control: the same request
as an identity without the right, or without a session, is refused. proof.json: setup as the privileged identity
expecting the protected marker, attack as the lower identity expecting it, twin control `"as": null` expecting
`{"status": [401, 403]}`. `bh-note finding "<title>" --severity <s> --class broken-access-control --url <url>
--proof <that proof.json> --summary "<...>" --not-proven "<...>" --counter "<...>" --severity-if "<...>"
--severity-why "<...>"`.

## Never
- Touch an object that is not owned by one of our identities, enumerate ids, or keep an admin action's effect.
- Give a role or an invitation to an address that is not one of ours.

## False positives
- The same answer for everyone is not a bypass; a 200 with an empty body or an error page is not either.
- An action the lower role is allowed by the product's own documentation.

## Watch
- A 403 from the edge (WAF, CDN) is not the application's answer; a 200 that is the app shell is not access.
- Order of checks 401, then 400, then 403: a 400 before the 403 is weak ordering, not a bypass.
- A backend-as-a-service behind the app (row policies written for "any authenticated user"): skills `supabase` and
  `firebase`.
