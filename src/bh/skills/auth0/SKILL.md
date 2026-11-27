---
name: auth0
description: Use when the app signs in through Auth0 (`*.auth0.com` or a custom login domain in the authorize URL, auth0-spa-js in the bundle). Tests how the app's own API checks audience, scope, roles and org_id.
---
<!--
Source: strix/skills/technologies/auth0.md, Strix (https://github.com/usestrix/strix), Copyright 2025 OmniSecure Inc.,
Apache License 2.0.
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form; the Auth0 tenant is a login host, never a
target: only the app's own API is tested, between our two identities; removed: callback-URL fuzzing on the tenant,
Management API use and the hunt for leaked machine-to-machine credentials, user enumeration, MFA brute force and
recovery-code guessing, password-grant logins, custom database script injection, searching public repositories
and CI logs for secrets, the "Pro Tips" list.
-->

# Auth0 (the app's side)

## When
- The login goes to `https://<tenant>.auth0.com/authorize` (or a custom login domain) with `client_id`,
  `audience`, `scope`; the bundle loads `@auth0/auth0-spa-js`, `auth0-react` or `auth0-js`.
- The tenant, its `/authorize`, `/oauth/token`, `/userinfo` and `/api/v2/` are login hosts: the gate refuses them
  unless your scope names them. Your target is the app's API that accepts Auth0 tokens.

## Do
1. From the recorded login (`bh-web net`): the tenant domain, `client_id`, `audience`, the scopes asked. Record
   them: `bh-note fact "auth0 config" -s "<tenant, client_id, audience, scopes>" -k recon`. The client id is
   public.
2. Role and permission claims: what the app's API decides from (`permissions`, `scope`, a namespaced roles claim,
   `org_id`). Read them from a token your identity can see (skill `jwt` for reading and changing it).
3. Scope and role enforcement on the API: an action of the higher role (skill `function-level-authz`) called by
   the identity whose token lacks the permission. Accepted = the API trusts a valid token without checking the
   permission.
4. Audience: if the program has two APIs or two apps on the same tenant, a token issued to your identity for one
   sent to the other. Accepted = audience not checked.
5. Organisations (B2B): the app's org-scoped routes as the identity of the other organisation (skill
   `multi-tenant`). The `org_id` of the token must win over any org selector in the request.
6. Metadata the app turns into rights: a profile field your identity can edit in the app (stored as
   `user_metadata`) that later shows up as a role or a permission. Change it on your own account, read the API's
   decision, put it back.

## Proof
The proof of the class you reached, on the app's API, between your two identities: `broken-access-control` for a
permission or role not checked (attack by the identity without the permission, control without a session), the
skill `multi-tenant` standard for `org_id`, the skill `jwt` standard for a token accepted with the wrong audience.

## Never
- Send anything to the Auth0 tenant beyond what the app's own login already did; never its Management API.
- Use a client secret, a machine-to-machine credential or a token found in a bundle, a repository or a log.
- Guess or loop MFA codes, recovery codes or reset tokens; log in with a password grant.
- Create users, or link a social account to an identity that is not one of yours.

## False positives
- (Strix) Callback URLs refused in every form: the tenant is configured well (and it is not our target anyway).
- (Strix) An API that checks `aud`, `iss`, `scope` or `permissions` on every request: the refusals are the control.
- (Strix) MFA enforced on every login of a sensitive app.
- (Strix) `app_metadata` writable only by the tenant's admins, not by the user.
- (Strix) Organisations bound in the token (`org_id`) and enforced by the API.
- The `client_id`, the tenant domain and the public signing keys: public by design.

## Watch
- Auth0 is the identity provider: a bug in the tenant is Auth0's or the program's configuration, reported only if
  the program lists the tenant in scope.
- Tokens the gate injects stay with the gate; only tokens your identity can read are yours to examine.
