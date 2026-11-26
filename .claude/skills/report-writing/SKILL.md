---
name: report-writing
description: Use when writing the title, summary or impact of a finding, or turning a verified finding into the report the operator will submit. No consequence for a user or the company, no finding.
---
Source: hermes/creative/bug-bounty-report-triptyque/SKILL.md (author: Hermes Agent, licence: MIT); merged from hermes/security/agent-de-conformite, hermes/bug-bounty/bug-bounty-proof-package, hermes/security/bug-bounty-methodology and hermes/security/live-recon/references/poc-format-mio.md (no licence stated).
Modified: translated; the "anti-AI score" goal, examples that steal cookies or list thousands of real users, HTML and server PoCs, and report templates holding tokens removed; title rule set to ours.
Role: hunter (title, `--summary`, `--not-proven`) and orchestrator (the report text). To merge with the Strix-based text of plan item L2 (counter-evidence, severity calibration). A program's own bar stays in the program skill.

# Report writing

## When
- You fill `bh-note finding` fields.
- A finding is `verified` and the triager PoC written by the harness must become a report.

## Do
1. Decide first: who is the victim, what crossed which boundary, what the attacker gained or changed. One of
   the three missing = not a finding. Record a fact instead.
2. Write the best case against your own finding (by design, attacker-supplied secret, seed data, excluded
   class), and what would change its severity. Keep both with the finding.
3. Title: the defect and the place, never the consequence.
   | Weak | Right |
   |---|---|
   | `IDOR` | `Order detail route does not check the order's owner` |
   | `XSS` | `Wishlist name is rendered unescaped on the account page` |
   | `Account takeover` | `Password reset accepts a user id from the request body` |
4. Three readers, three short parts:
   - the triager in a hurry: numbered steps, one request per step, the expected answer under each, variables
     (`$TARGET`, the two test accounts) defined once at the top;
   - the sceptical engineer: the two answers side by side (attack and control) and the one line that differs;
   - the product owner: two or three plain sentences on the impact, then one fix, the simplest that works.
5. Impact is what you observed, in the past tense:
   | Do not write | Write |
   |---|---|
   | "could allow an attacker to" | "user-a read the name and address stored on user-b's order" |
   | "risk of data leakage" | "the answer holds one complete order owned by user-b" |
   | "potentially critical" | the severity, with the metric that carries it |
6. Evidence: raw request and answer, UTC time, one or two captures at most. For an AI finding add what the
   program asks: exact URL or application, settings changed, every prompt word for word, conversation id,
   k/N.
7. Say what you did not prove.

## Never
- A conditional: "could", "might", "probably", "potentially", "I think". Each one is a reason to close.
- Anything wider than what was observed: no "all users", no counts you did not measure.
- Real people's data, a session value, a key, or credentials in the text. Accounts are named user-a, user-b.
- Dress the text to look human-written. A human reads and owns every report before it is sent; that is the
  rule, not a style.
- Three fixes where one is enough, or a severity above the proof.

## What does not pay
Attacker equals victim; the model's own words as only evidence; version banners; missing headers; a public
key reported as a secret; a chain with an untested link.

## Watch
- If the triager must open the report to understand the title, rewrite the title.
- A step count that follows the logic (login, plant, attack, control), not every click.
- A run-and-check script is welcome only when it does what the numbered steps do and nothing more.
