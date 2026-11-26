---
name: cvss-from-evidence
description: Use when a severity or a CVSS 3.1 vector is written or judged. Each metric must rest on something the proof shows; the score a model writes by default is almost always too high.
---
Source: hermes/security/cvss-validator/SKILL.md (no author or licence stated; based on the FIRST CVSS v3.1 specification).
Modified: translated and shortened; two rules corrected against the specification (marked below); a per-program reward estimator and a real program's severity table removed.
Role: judge and orchestrator; the hunter when a vector is asked for. The score itself is computed by the host from the vector (plan item T28), never by hand.

# CVSS from evidence

## When
- A finding carries a severity, or a vector is about to be written for a platform that asks for one.
- You review a severity someone else wrote.

## Do: one metric, one piece of evidence
| Metric | Choose | Evidence needed |
|---|---|---|
| Attack Vector | N if reachable over the network; A if only from a logically adjacent or restricted network; L or P for local or physical | where your request came from |
| Attack Complexity | L if it works every time; H if it needs a race, a position on the path, or facts the attacker must first gather | k/N of your runs |
| Privileges Required | N only with no session at all; L for any ordinary account or key; H for an admin | the `as` of the attack step |
| User Interaction | N if nobody else does anything; R if a victim must open, click or submit | what the victim identity did |
| Scope | U unless the proof shows impact on a component under another security authority | the component in the last step |
| Confidentiality / Integrity / Availability | N, L, H from what was actually read, changed or stopped | the body or the read-back |

Rules:
1. A score is worth what the proof shows. Three JSON fields leaked is not "all data".
2. Score the step you ran, not the chain you imagine.
3. No working proof: never Critical.
4. Missing headers and other defence-in-depth gaps are never High.
5. The program's own severity scale wins over CVSS when it has one: read it and map to it.

Corrections to the source (check the FIRST specification before relying on either):
- The source says a flaw exploitable only from inside an intranet is Adjacent. The specification keeps
  Network for anything reachable through the network stack, and reserves Adjacent for logically adjacent or
  administratively restricted networks. When in doubt, say which reading you used.
- The source says C:H needs all data. The specification also gives H when the limited data disclosed has a
  direct, serious impact (an administrator's credential, for instance).

## The default vector to distrust
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` is what automated pipelines write for anything. Review it in this order:
- S:C to S:U unless a boundary crossing is shown;
- C:H/I:H/A:H down to what was observed (often C:L/I:N/A:N);
- PR:N to PR:L as soon as any account, key or network isolation is needed;
- AC:L to AC:H when it needs a race or prior knowledge.

Bands: 0.1 to 3.9 Low, 4.0 to 6.9 Medium, 7.0 to 8.9 High, 9.0 to 10.0 Critical.

## Never
- Raise a severity as a judge: confirm or lower.
- Justify a metric with a conditional ("could", "might", "potentially").
- Estimate a bounty from a score.

## Watch
- Programs that rate on business impact (MSRC's bug bars, for instance) do not use CVSS: the bar of the
  program skill decides, this skill only keeps the reasoning honest.
- A theoretical deviation from a specification that is not exploitable in practice is a documentation issue.
