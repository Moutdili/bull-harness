---
name: multi-tenant
description: Use when the product has organisations (tenants, workspaces) and your two identities sit in two of them
---
<!--
Source: written for bull-harness (W3-H), no third-party text. Ideas cross-checked with the tenant sections of Strix
broken_function_level_authorization.md, supabase.md, firebase.md and auth0.md (Apache-2.0), none copied.
modified: nothing removed (original text).
-->

# Multi-tenant isolation

## When
- The product groups users in organisations (tenants, workspaces, teams, projects with members), and each of
  your two identities belongs to its own organisation.
- A request names the organisation: a path segment (`/orgs/{org}/...`), a subdomain, a header
  (`X-Org-Id`, `X-Tenant`), a query or body field (`orgId`, `workspace_id`), or a claim in a token.

## Do
1. Map both organisations: as each identity, the organisation id and two or three org-scoped objects (projects,
   documents, members, invoices), from your own answers. Never guess an id.
2. Plant a marker in the victim organisation: an object of the victim identity's organisation holding `bhx` and
   5 digits, or a `bh-note canary`, in a place private to that organisation (a private project, an internal
   note, a member-only document). Read it once as the victim: the setup.
3. From the attacker identity, one change at a time, on reads first:
   - the victim organisation's id in the selector (path, subdomain, header, field), the attacker's session kept;
   - the victim's object id under the attacker's own organisation path (`/orgs/<attacker org>/docs/<victim doc>`);
   - an org-scoped list or search with the selector removed or set to the victim's org.
4. Writes only after a read crossed, and only on the marked object: rename it to a second marker, then read it
   back as the victim. Put it back.
5. Invitations and membership: invite only the other identity, by its own address (the gate refuses any other
   recipient). Then test what membership checks miss: the invitation accepted by the wrong identity, a role
   chosen in the accept request, access kept after removal.
6. Exports, reports, webhooks and search indexes are where tenant filters are forgotten: one request each.

## Proof
proof.json, the standard of `broken-access-control` (an object only its tenant may read):
- `setup`: as the victim identity, the read of the marked object, expecting the marker;
- `attack`: the same read as the attacker identity (the other organisation), expecting the marker;
- `control`: the same read with `"as": null`, expecting 401, 403 or a redirect to login. The attacker's read of
  its own organisation's equivalent (the route works for it) goes in `--summary`: its path differs, it is no twin.
Record with `--class broken-access-control`; `--not-proven`: which other organisations were not touched (all).

## Never
- An organisation that is not ours: no guessed, listed or found organisation id outside your two identities'.
- An invitation sent outside our accounts, or to an address that is not one of your identities'.
- Join, leave or delete an organisation, or remove a member, except what step 5 needs between your two.
- Read more than the marked object once it crossed: one object proves the boundary.

## False positives
- The victim's object is public or shared with the attacker's organisation by design (a public link, a
  marketplace listing, a shared channel).
- A 200 with the attacker's own organisation's data: the selector was ignored, the session decided.
- An id resolvable in both organisations because it is the same shared object (templates, demo data).
- Org names or member counts on an invitation or join page: shown by design to an invitee.

## Watch
- On personal accounts with no organisation, the class is `idor`: card `idor`, not this skill.
- Two identities in the same organisation with different roles: skill `function-level-authz`.
- A token whose claims carry the organisation (`org_id`): the server must take it from the token, not from the
  request; a request selector that overrides the claim is the bug.
