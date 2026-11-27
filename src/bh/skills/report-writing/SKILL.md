---
name: report-writing
description: Use when filling `bh-note finding` (title, summary, honesty fields, severity), closing a candidate, or turning a verified finding into the report the operator submits.
---
<!-- Origins: (1) ../inputs/skills-audit/skills/report-writing/SKILL.md, itself from Hermes
creative/bug-bounty-report-triptyque (author: Hermes Agent, licence: MIT), merged there with Hermes
security/agent-de-conformite, bug-bounty/bug-bounty-proof-package, security/bug-bounty-methodology and
security/live-recon/references/poc-format-mio.md (no licence stated); (2) strix/skills/analysis/counterevidence.md and
strix/skills/analysis/severity_calibration.md (Strix, Apache-2.0).
Modified: merged and condensed, Strix's tools mapped to ours (`bh-note done --outcome`, `bh-note cover`, the three
honesty fields); removed: Strix's static-only findings without a replay, its CVSS vector mechanics and severity
examples that aim at internal services; from the first origin, nothing more than its own removals (the "anti-AI
score" goal, cookie-stealing examples, report templates holding tokens). A program's own bar stays in its skill. -->
# Report writing, closing a candidate, calibrating severity

## When
- You fill `bh-note finding` fields, or close an intent (`bh-note done ... --outcome`).
- A finding is `verified` and the triager PoC written by the harness must become a report.

## Do
1. Decide first: who is the victim, what crossed which boundary, what the attacker gained or changed. One of the
   three missing = not a finding: record a fact instead. No consequence for a user or the company = not a finding.
2. Close every candidate in one of three states, never "I moved on":
   - `confirmed`: a replayable proof (proof.json with its twin control, or an observation proof);
   - `ruled_out`: you name the control that makes it safe, where it runs, and that it runs on the attacker's path
     before the effect: "safe because <control> at <observed behaviour> <does what> before <sink>";
   - `open_proof_gap`: plausible, not confirmed, no control named. Record it as such
     (`bh-note done I<n> "<gap>" --outcome open_proof_gap`, `bh-note cover ... retry`); never tidy it into
     `ruled_out`.
3. Write the best case against your own finding: argue the other side for real (the guard you may have missed, by
   design, an attacker-supplied secret, seed data, an excluded class). That is `--counter`; if you found nothing,
   say what you checked, not "none".
4. Severity: a conclusion reached after reachability and the counter case, never an opening position. Rate the
   weakness you proved, not the worst case reachable from it. `--severity-why` says why; `--severity-if` names the
   one piece of evidence that would raise or lower it ("the same route answering without a session would make it
   critical"). The program's own bar (its skill) decides the words, this skill decides the honesty.
5. Title: the defect and the place, never the consequence.
   | Weak | Right |
   |---|---|
   | `IDOR` | `Order detail route does not check the order's owner` |
   | `XSS` | `Wishlist name is rendered unescaped on the account page` |
   | `Account takeover` | `Password reset accepts a user id from the request body` |
6. Three readers, three short parts:
   - the triager in a hurry: numbered steps, one request per step, the expected answer under each, variables
     (`$TARGET`, the two test accounts) defined once at the top;
   - the sceptical engineer: the two answers side by side (attack and control) and the one line that differs;
   - the product owner: two or three plain sentences on the impact, then one fix, the simplest that works.
7. Impact is what you observed, in the past tense:
   | Do not write | Write |
   |---|---|
   | "could allow an attacker to" | "user-a read the name and address stored on user-b's order" |
   | "risk of data leakage" | "the answer holds one complete order owned by user-b" |
   | "potentially critical" | the severity, with the observation that carries it |
8. Evidence: raw request and answer, UTC time, one or two captures at most. For an AI finding add what the program
   asks: exact URL or application, settings changed, every prompt word for word, conversation id, k/N.
9. Say what you did not prove (`--not-proven`).

## Proof
The report carries the proof the harness replays: the attack and its twin control side by side, the one line that
differs, k/N for an observation proof. A report without a replayable proof and its control is not sent.

## Never
- A conditional: "could", "might", "probably", "potentially", "I think". Each one is a reason to close.
- Anything wider than what was observed: no "all users", no counts you did not measure.
- Real people's data, a session value, a key, or credentials in the text. Accounts are named user-a, user-b.
- Dress the text to look human-written. A human reads and owns every report before it is sent; that is the rule,
  not a style.
- Three fixes where one is enough, or a severity above the proof.

## False positives
These do not rule a candidate out (each is an `open_proof_gap` at best):
- generic trust in a library ("the framework escapes this"): an HTML escaper does nothing in a script context;
- a control on a different path (a sibling route, a batch job, an older API version), or at the wrong time (an
  ownership check after the object was returned), or one that can fail open;
- a safe sibling: one guarded call says nothing of the others;
- missing information ("could not find a caller") or difficulty ("needs an account I do not have");
- "an operator could configure a filter", "off by default": what ships and is reachable counts;
- being internal or admin-only lowers severity; it does not delete the finding.
These do not pay: attacker equals victim; the model's own words as only evidence; version banners; missing headers;
a public key reported as a secret; a chain with an untested link; a session weakness that needs a secret of the
victim the same finding does not show how to obtain.

## Watch
- High or critical only if all hold, else one level down: the path is realistic and in scope, the attacker position
  is one an attacker can obtain, the impact was shown (not one record called "mass"), the counter case found no
  constraint that holds, reachability was observed, you would defend it in front of the triager.
- Usually not above medium: self-XSS, clickjacking on a harmless action, missing headers, an open redirect alone,
  "could matter if chained", anything that already needs admin access.
- Downgrade, never delete: a constraint lowers the severity and is said in the report. Missing evidence lowers your
  confidence, not the severity floor.
- If the triager must open the report to understand the title, rewrite the title.
- A step count that follows the logic (login, plant, attack, control), not every click.
- A run-and-check script is welcome only when it does what the numbered steps do and nothing more.
