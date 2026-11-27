---
name: proof-package
description: Use when a lead looks like a finding, before `bh-note finding`, or when a finding came back `needs-proof`. Builds the baseline/attack diff on your two identities; no diff, no finding.
---
<!--
Source: hermes/bug-bounty/bug-bounty-proof-package/SKILL.md (no author or licence stated).
Modified: translated; mapped to `q`, `qq` and proof.json; removed the id-enumeration example, two personal e-mail addresses, a local PoC script we do not have, and the "title names the impact" rule (ours: defect and place).
Role: hunter. The pre-submission checklist of the same source is the skill `pre-submit-review`.
-->

# Proof package: no diff, no finding

## When
- A request seems to return or change something it should not.
- You are about to write a proof.json.
- You hesitate between "bug" and "by design".

## Do
1. The diff. One request as the owner on its own object (baseline), the same request as the other identity on
   that object (attack). `qq <url>` prints status, size, hash and `==` for each identity and anonymous.
   - Attack `==` what anyone gets: not a bug. `bh-note fact "<route>: no differential" -k dead-end`. No
     rewording saves it.
   - Different: find what differs. The owner's data in the attacker's body = candidate.
2. Change one thing only between baseline and attack: the object id or the identity. Same method, same
   headers, same body. That is what shows the access control is the cause, and nothing else.
3. The victim's data must be yours and recognisable: put a marker (`bhx` and 5 digits) or a `bh-note canary`
   in the victim identity's object before the attack.
4. With and without. A parameter, header or token you think grants access is sent with it AND without it.
   Same answer both ways = accepted, not needed: not a bypass.
5. Rule out the cache: replay once cold, with a throwaway query parameter, and as the other identity.
6. Write the proof.json: `attack` = the request showing the impact, `control` = its twin that must fail
   (other identity, no session, benign value). Expect a marker only the victim owns, never a bare 200.
7. Say what you did not prove in `--not-proven`, then `bh-note finding ...`.

## Proof
- A 200 proves nothing. A body that holds the victim's marker does.
- Minimum data: one record, one field. Never a dump.
- CSRF is the exception to the diff (the forged request is a valid request): skill `csrf`.
- Two findings that combine: skill `chaining`.

## Never
- Enumerate ids to "show scale". One object of your other identity proves it.
- Use a session, token or secret the attacker would not have. A PoC that needs the victim's own token is the
  victim robbing itself.
- Present the output of a tool, or the claim of another agent, as proof: replay the key request yourself and
  read the header or field that carries the mechanism.

## False positives
- The same answer for everyone: public by design.
- A 200 with an empty body, an error page inside a 200, or the single-page-app shell.
- "Accepted" mistaken for "necessary" (step 4).
- Seed or demo content: the vector may be real, the claimed impact is not.

## Watch
- A proved negative is a result, not a failure: "quantity capped by stock", "price recomputed by the server",
  "output escaped twice". Record it with the control you ran (`-k dead-end`) and change target. Do not rephrase
  the same lead hoping for another answer.
- The same root cause on several routes or hosts is one finding with variants. Say so in `--summary`.
