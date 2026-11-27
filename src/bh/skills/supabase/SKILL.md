---
name: supabase
description: Use when the app's bundle or CSP names `<ref>.supabase.co` or a `sb_publishable_` key. Tests row-level security table by table with PostgREST error codes; the key itself is never the finding.
---
<!--
Source: hermes/.archive/supabase-postgrest-security/SKILL.md; merged from hermes/.archive/supabase-postgrest-audit, hermes/arsenal-nemesis/references/supabase-rest-recon.md and hermes/bug-bounty/recon-methodology (no author or licence stated).
Modified: translated; a real target, self sign-up, anonymous insert and delete probes, payment-intent creation and table-name wordlists removed; scope and identity rules are ours.
Role: hunter. Technology skill (plan item D21).
False positives merged from Strix strix/skills/technologies/supabase.md (Copyright 2025 OmniSecure Inc.,
Apache-2.0), which has no "False Positives" section: two lines taken from its "API Keys and Signing Keys" and
"Auth & Tokens" notes, marked "(Strix)".
Modified from Strix (Apache-2.0) by bull-harness: those two notes rewritten as false positives; nothing else taken.
modified (bull-harness W3-H): the unmeasured mention on the session injected on the project host removed (not
measured; the Watch line keeps the fallback when no session is injected).
-->

# Supabase / PostgREST

## When
- The bundle or the `Content-Security-Policy` (`connect-src`) names `https://<ref>.supabase.co`.
- First check the project host is in scope: one `q` to it. A `403` with `X-BH-Gate: denied` is final:
  record the fact and stop.

## Do
1. Key and project: in the crawl output, `grep -oE 'sb_publishable_[A-Za-z0-9_-]+'` and
   `grep -oE 'https://[a-z0-9-]+\.supabase\.co'`. Older projects use a JWT-looking anon key.
2. Table names come from the app's own requests (`bh-web net`, the bundle), not from a wordlist.
3. Read test, per table, smallest read:
   `q -n 600 -H 'apikey: <key>' -H 'Authorization: Bearer <key>' '<project>/rest/v1/<table>?select=*&limit=1'`
   | Answer | Meaning |
   |---|---|
   | `42501 permission denied for table X` | row-level security closes the table |
   | `200 []` | readable by this role and empty: open, nothing leaked yet |
   | `200 [ {...} ]` | rows readable with the public key |
   | `PGRST205 ... Perhaps you meant the table 'public.Y'` | wrong name; `Y` is a real table |
   | `42703 column X does not exist` | the table is readable; the column is not there |
   | `Secret API key required` on `/rest/v1/` | the root listing is locked; tables may still answer |
   | `No API key found in request` | the `apikey` header is missing |
4. Differential, the core of a finding: compare tables. Most closed and a few open = a forgotten policy,
   not a choice. List them side by side.
5. As each identity: repeat step 3 with the session the gate injects (`q -a user-a ...`, `q -a user-b ...`).
   user-b reading user-a's row = the proof (skill `proof-package`).
6. Writes only on your own rows: as user-a, PATCH one of your rows to the value it already has; then as
   user-b the same PATCH on user-a's row. Always read the row back: a `204` with zero rows changed is the
   policy filtering, not a write.
7. Settings, one request: `<project>/auth/v1/settings` with the `apikey` header. `disable_signup: false`
   with `mailer_autoconfirm: true` = anyone gets an authenticated role. Record it as a fact.
8. Storage: only buckets the app itself uses, `<project>/storage/v1/object/public/<bucket>/`.
9. Link what a public table gives (ids) to the app's own API routes: that is where an IDOR chain starts
   (skill `chaining`).

## Proof
proof.json: `attack` as the other identity (or `"as": null` with the public key in `headers`) reading the
row that holds user-a's marker; `control` on a table that answers `42501`, or the same read without the
`apikey` header.

## Never
- Sign up an account yourself, even where it is open: `bh-note blocked account "open signup: needs an
  enrolled identity"`.
- Insert, update or delete a row that is not owned by one of your identities, no-op included.
- `limit` above 1 on a table that may hold other people's data. Real people's rows on screen: stop,
  `bh-note blocked third-party-data "<table, no content>"`.
- Confirm a payment, or create payment objects in someone else's name.

## False positives
- The publishable key in the bundle, and payment `pk_live_` keys: public by design.
- `200 []` reported as a leak, or as protection: it is neither (step 3).
- A `200` or `204` on a write or delete with no row changed.
- A `200` HTML answer on an unknown API path of the front host: the app shell, not an endpoint.
- Seed rows (placeholder addresses, test items): the vector is real, the impact is not shown.
- (Strix) The `apikey` header names the project, not a user: a request that passes with the publishable key
  alone has not shown a signed-in user, nor anyone's data.
- (Strix) A function that skips the platform's JWT check (`verify_jwt=false`) but checks a secret or a webhook
  signature itself is not public: the refusal of an unsigned call is the control working.

## Watch
- The gate injects a session only toward origins it holds one for. If `q -a user-a` on the project host
  answers like the anonymous request, the identity has no token there: record it and test through the app's
  own API instead.
- Order of checks on the app's API with a valid session: 401 (no session), then 400 (parameters), then 403
  (role). A 400 before the 403 is weak ordering, not a privilege escalation.
- Realtime wants a real JWT, not the publishable key; websocket rules of the gate apply.
