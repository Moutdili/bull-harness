---
name: function-level-authz
description: Use when your two identities hold different roles (admin and member, owner and viewer) and the app has actions only the higher role sees. The lower role calls each such action directly.
---
<!--
Source: strix/skills/vulnerabilities/broken_function_level_authorization.md, Strix (https://github.com/usestrix/strix),
Copyright 2025 OmniSecure Inc., Apache License 2.0.
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form, between our two identities, with the proof
standard of the class `broken-access-control`; removed: reaching internal services through SSRF, gRPC reflection,
batch and alias tricks, identity headers sent to override the session, retries of approve and finalize endpoints
on objects of others, cache-key confusion, the "Pro Tips" list.
-->

# Function-level authorization

## When
- The scope gives you two identities of different roles in the same account or organisation (admin and member,
  owner and viewer, staff and customer).
- The higher role sees actions the lower one does not: an admin page, a hidden button, a settings section, a
  GraphQL mutation used only by the admin UI, a role or invitation endpoint.
- First pass: `bh-authz` (mapper) shows a higher role's answer given to a lower role. This skill is the method
  by hand.

## Do
1. As the higher role, do each privileged action once, on objects of your own account, while the browser records
   (`bh-web net`, or `bh-browse --as <higher identity> --routes`). The list of calls is the map: method, URL,
   body. Note each as a fact.
2. Pick the actions that matter: role and permission changes, invitations, exports, deletion of your own test
   objects, billing or plan settings shown (not used), security settings (2FA reset, verification overrides).
3. Replay each call as the lower role, same method, same body: `q -a <lower identity> -X <method> -j '<body>'
   <url>`. One request per action.
4. Read the effect, never the status: read the object back as the higher role. A 200 that changed nothing is a
   refusal; a 204 is not a success until a read shows the change.
5. Variants, one each, only for an action refused in step 3: the same action through another path the app uses
   (an older API version, the GraphQL mutation instead of the REST route, another method on the same route).
6. Put every object back as it was (role, setting, member list).

## Proof
proof.json, the standard of `broken-access-control`:
- `setup` (optional): the higher role doing the action legitimately, to show what success looks like;
- `attack`: the same request as the lower role, then a read expecting the effect as a marker (the new role, the
  exported data, the changed setting with a `bhx` value);
- `control`: the same request with the right absent, `"as": null` (no session), expecting 401, 403 or a redirect
  to login.
Record it with `bh-note finding ... --class broken-access-control`.

## Never
- Act on an account, organisation or object that is not one of your identities'.
- Raise your lower identity's role and keep it: undo at once and say so in the finding.
- Send identity or role headers (`X-User-Id`, `X-Role`) to override the session: the identity is the gate's.
- Delete anything but a test object your higher identity created for the test.

## False positives
- (Strix) A route named "admin" that is public and documented: the same answer for everyone.
- (Strix) A preview or beta feature open to all roles by the product's own policy.
- (Strix) A stubbed admin endpoint that answers success with no side effect: read the object back.
- The UI hides a button the lower role is in fact allowed to use: check the product's role table.
- An action that only touches the lower role's own object (that is the role's right, not a bypass).

## Watch
- Object-level access (another user's object, same role) is the card `idor`; another organisation's data is the
  skill `multi-tenant`.
- An action refused at the edge (WAF, CDN 403) is not the application refusing: compare with the control.
- Exports and reports run later in a job: read the job's result as the lower role too.
