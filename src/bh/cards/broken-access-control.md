## Broken access control (vertical, cross-tenant, function level)
When: the program gives identities with different roles (`admin`, `member`, `guest`) or tenants (`@A`, `@B`): see
`BH_IDENTITY_ROLES` in the identities line. Admin routes, settings, exports, invitations, billing, tenant switches.
Do:
1. Map as the most privileged identity first, so its admin and settings routes land in the surface.
2. Run `bh-authz` (owner = the privileged identity): every route is replayed as each other identity and anonymous.
   `[vertical]`: a lower role got what only the higher role gets. `[horizontal]`: another tenant got this tenant's data.
3. For each candidate, read the raw answers: the protected data (owner marker, admin-only field) must be in the
   lower identity's answer, not a public shell. Then use the `proof.json` it wrote (attack: lower identity,
   control: no session or a third identity).
4. Function level: actions the lower role must not trigger (invite, change role, export), only on objects of our
   own identities; the owner re-reads the object to see the effect.
5. Cross-tenant: an object id of tenant A requested as tenant B, in the path, body, query, or a tenant header.
Watch: the same answer for everyone is not a bypass; a 200 with an empty body or an error page is not either.
Never: touch an object that is not owned by one of our identities, enumerate ids, or keep an admin action's effect.
