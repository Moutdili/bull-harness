---
name: false-positive-traps
description: "Use when about to record a finding or a CANDIDATE, and when judging one: the traps that make a claim false (parameter not needed, by design, SPA fallback, public keys, seed data, WAF answers)."
---
<!--
Source: hermes/review-cavaliers/SKILL.md; merged from hermes/review-nemesis, review-ombre, review-kairos, review-chaos, hermes/bug-bounty/llm-hallucination-bug-bounty, hermes/arsenal-cavaliers and hermes/bug-bounty/infomaniak-pentest/references/by-design-verification.md (no author or licence stated).
Modified: translated; the self-awarded /100 score, the "50+ payloads per mission" target, real target names, unverifiable statistics and the advice to ask a third-party model were removed.
Role: hunter (before `bh-note finding`) and judge (as a list of ways a claim is wrong).
modified (bull-harness W3-H): a Proof section added (the common form asks for one); the other sections unchanged.
-->

# False-positive traps

## When
Before every `bh-note finding` or `CANDIDATE` fact. Answer each question with a file or an output line.

## Do: five questions
1. Does it exist? You sent the request and hold the answer. A list of payloads without answers is nothing.
2. With and without? The secret, header, parameter or token you found is tested with it and without it. Same
   status and body both ways = it is accepted, not needed. Not a bypass.
3. By design? Look for the product's own signals: a `public` visibility field, documented behaviour, the same
   behaviour in the open-source product the target is built on, a free product with guest access. If the
   upstream default does the same, it is the feature.
4. Real data? Before calling it a leak, check the data is not seed or test content: repeated patterns,
   placeholder addresses, a test environment. Seed data: the vector is a fact, the impact is not proved.
5. Proof kept? The request, the answer and the control are on disk and named in the finding.

## Six ways a model invents a finding
| Invented | Check |
|---|---|
| Code: a flaw "seen" in a summary | read the real source or response, not the summary |
| Endpoint or parameter | one live request |
| CVE on a version it does not affect | exact version read from the target, then the advisory's range |
| Credential | never accept one that was not read from a response |
| Severity raised to please | recompute from what was proved (skill `cvss-from-evidence`) |
| Scope | re-read the scope block; a gate refusal is final |

## False positives by family
Access control
- A 403 or challenge from the edge (WAF, CDN) is not the application refusing: it is not a control, and its
  absence is not a bypass. A marker header of the origin, present or not, tells the two apart.
- An empty 200, or an empty list, is not "protected": on a row-level-security backend it means readable and
  empty. It is not a leak either: a latent risk, say so.
- A delete or update that answers 200 or 204 and touched zero rows proves nothing: read the object back.

Single-page apps and static hosts
- An unknown path that answers 200 with HTML is the app shell. Signature: the same size on every path. A
  `.env` or `/api/x` answered that way is not exposed. Confirm an API route with a POST (405) or its JSON type.
- A source map that returns HTML is not a source map. Check the content, not the status.

Secrets in bundles
- Publishable keys are public by design (payment `pk_live_`/`pk_test_`, Supabase `sb_publishable_`, analytics
  SDK keys). The finding is what the key lets you read, never the key.
- Library constants look like secrets: test fixtures of auth libraries, the base64url alphabet.
- An empty grep is not "no secret": check the pattern on a string you know is there before concluding.

Versions and CVEs
- "Probably vulnerable" does not exist. No confirmed version, no CVE lead. A banner is a fact for the board.

Chains
- "A + B + C = admin" with one link untested is a theory. One request per link before pivoting; write why
  you pivoted.

## Proof
This skill proves nothing itself: it tests a proof. Each answer above names a file or an output line; the
proof.json is built with the skill `proof-package` (the attack, and the control that would have failed if you
were wrong).

## Never
- Send a payload that could create or change a real record "to validate". A bogus id answering a clean 404 or
  400 already shows server-side validation: quote it as counter-evidence.
- Set a volume target for yourself. Ceilings, never quotas.

## Watch
- The judge is told your summary may be wrong. Give it the control that would have failed if you were wrong.
- When your tool refuses something in the page (a storage write, a click), that is the harness, not the
  target: do not report it as the target's behaviour.
