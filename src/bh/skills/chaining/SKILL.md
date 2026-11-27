---
name: chaining
description: Use when the board holds two or more facts or findings on one program, or a finding is too weak to pay alone (self-XSS, open redirect, permissive CORS).
---
<!-- Origin: ../inputs/skills-audit/skills/chaining/SKILL.md, itself from Hermes vuln-synthesizer/SKILL.md and its
references/web-saas-chain-playbook.md, merged there with Hermes bug-bounty/bug-bounty-proof-package (chain table) and
review-kairos (no author or licence stated). Modified: rubrics put in this harness's order (a Proof rubric added from
its step 5), skill names of this harness in the links; removed there already: findings and names of real programs,
the "sum of CVSS times a synergy factor" chain score. -->
# Chaining

## When
- A new fact lands next to older ones (`bh-note frontier`).
- A finding alone would be closed "informative": self-XSS, open redirect, a public id list, a permissive CORS.

## Do
1. Give each fact a type: secret or credential, authentication, access control, information, client side,
   configuration. A chain joins at least two different types.
2. For each pair, one question: does A give what B was missing (an id, a session, a position, a trusted origin)?
   No = not a chain, do not force it.
3. Pairs that pay:
   | Weak alone | Joined with | Becomes |
   |---|---|---|
   | self-XSS | CSRF on the form that stores it (skill `csrf`) | script running for another account |
   | open redirect | an OAuth or reset flow that trusts the redirect (skill `oauth-oidc`) | token sent off-site |
   | read IDOR | write IDOR on the same object | takeover of the object |
   | ids from a public table or list | an API route keyed by those ids | cross-account read |
   | permissive CORS | a cookie-authenticated endpoint | cross-origin read of account data |
   | framing allowed | a one-click sensitive action | forced action |
   | open sign-up with auto-confirm | policies written for "any authenticated user" | data open to anyone |
4. Test every link: one request per link, each with its own control, before you move to the next. Write why you
   pivoted: `bh-note intent "chain: <A> -> <B>" --kind test --basis F<n> --recall <R-id or none>`.
5. Record it as one finding: `--summary` names each link and its actor; `--not-proven` names the first link you
   did not run.

## Proof
One proof.json for the chain: setup steps in order, the last `attack` step shows the final impact, the `control`
breaks one link (the same final request without the first link's effect) and expects the final step to fail.
`bh-note finding "<title>" --severity <the final impact's> --class <the final link's class> --url <url> --proof
proof.json --summary "<link 1 (actor) -> link 2 (actor)>" --not-proven "<first link not run>" --counter "<...>"
--severity-if "<...>" --severity-why "<...>"`.

## Never
- Claim past the last link you ran. "A + B + C = admin" with C untested is a theory.
- A link that goes through a real user, a third party, or an object that is not yours.
- Add severities together. The severity of a chain is the severity of its final, proved impact.

## False positives
- Two findings that are the same root cause seen twice.
- A link that only works with a secret the attacker would not have.
- A chain whose first link is excluded by the program: the whole chain usually is.

## Watch
- "Nothing new by crossing" is a valid result. Most controls of a well-built stack hold; record the pairs you tried
  as dead ends (`bh-note fact "chain <A> x <B>: no link" -k dead-end --why approach`) so the next agent does not
  redo them.
- The report of a chain follows the skill `report-writing`.
