---
name: mass-assignment
description: Use when an API creates or updates your own object from a JSON or form body (profile, settings, project). Adds a field you may not set (role, isAdmin, verified, plan) and reads the object back.
---
<!--
Source: strix/skills/vulnerabilities/mass_assignment.md, Strix (https://github.com/usestrix/strix), Copyright 2025
OmniSecure Inc., Apache License 2.0.
Also: inputs/skills-audit/FUSIONS.md, section "Classes T41", row "Affectation de masse" (Hermes
mass-assignment-prototype-pollution, no licence stated): the field list and the nested, array and XML shapes.
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form, on our own objects only; removed:
ownership and tenant moves onto objects of others, "fuzz systematically" and the sensitive-field dictionary run as
a list, race-and-reorder tricks, billing and credit changes, signup-time escalation (we never sign up), the "Pro
Tips" list.
-->

# Mass assignment

## When
- A create or update route takes a body that mirrors the object: `PATCH /api/me`, `PUT /api/projects/{id}`, a
  GraphQL input type, a settings form.
- The answer or the app's own reads show fields the form never sends: `role`, `isAdmin`, `verified`, `plan`,
  `permissions`, `status`. Those are the candidates, read from the app, not from a list.

## Do
1. Baseline on your own object: read it (`q -a <identity> <read url>`), keep the value of each candidate field.
2. The normal update, as the app sends it (the body from `bh-web net` or the bundle), plus ONE extra field:
   `q -a <identity> -X PATCH -j '{"displayName":"bhx12345","role":"admin"}' <url>`
   One field per request: `role`, `isAdmin`, `verified`, `plan`, `balance`, `permissions`.
3. Read the object back. The status says nothing: a 200 that silently dropped the field is the normal case.
4. The field changed: test what it gives. A role or flag that opens an admin route, a plan that opens a paid
   feature, `verified` that lifts a restriction. One request on that route as this identity.
5. Shapes, one request each, only on a field the server echoed or named in an error: nested
   (`{"user":{"role":"admin"}}`, `profile[role]=admin`), array (`roles[]=admin`), the same body as form-encoded,
   or as XML when the route takes it.
6. Put the field back to its old value. If it cannot be put back, say so in the finding.

## Proof
proof.json, on your own object; the other identity never sent the field:
- `setup`: the update with the extra field, as the identity under test;
- `attack`: as that identity, the read (or the privileged route of step 4), expecting the forbidden value as a
  marker (`"role":"admin"`, the admin page's own content);
- `control`: the same read as the other identity, which only sent the normal update, expecting the old value or a
  refusal.
The proof follows the standard of `broken-access-control` when step 4 opened a higher role's action.

## Never
- Send the field on an object that is not yours, or move an object to another owner, account or organisation.
- Change a balance, a price, a credit or a plan that bills: a paid feature is shown, never consumed.
- Loop a list of field names. The candidates come from what the app shows.

## False positives
- (Strix) The server recomputes the field (plan, price, role) whatever the client sends: the read shows the old
  value.
- (Strix) A field marked read-only and refused the same way in every encoding.
- (Strix) A change visible only in the page you edited, never stored: no persisted effect.
- The field is stored but nothing reads it: no access changes. A fact, not a finding.
- `verified: true` on an account the product verifies anyway at the next step.

## Watch
- The answer to the update may echo your field even when it was not stored: always read it back separately.
- A field refused on `PATCH` may be accepted on the create route, or on a bulk route: one request each.
- An ownership field (`ownerId`, `orgId`, `tenantId`) belongs to the skills `idor` and `multi-tenant`, not here.
