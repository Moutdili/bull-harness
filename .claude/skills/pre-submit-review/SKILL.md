---
name: pre-submit-review
description: Use when a finding is `verified` and before the operator submits it, or after a platform closed a report (invalid, informative, duplicate, not reproducible). Last checks and how to answer a rejection.
---
Source: hermes/bug-bounty/bug-bounty-proof-package/SKILL.md; merged from hermes/security/agent-de-conformite/SKILL.md and hermes/bug-bounty/glasswing-cavalier/SKILL.md (no author or licence stated in any of them).
Modified: translated; aligned on the board and the judge; removed "credentials in the report", the id-enumeration wording, reverse-shell examples and a third-party validation tool.
Role: orchestrator, on the host. A human reads and submits. Nothing here sends anything to a platform.

# Pre-submit review

## When
- A `submit` todo exists for a finding (`bh todo`, `bh finding <id>`).
- A report came back closed and you must decide: more proof, a chain, or drop it.

## Do: the checklist (every line needs a file or an output line; a line without one is a no)
1. Replay on the day: `uv run bh verify <scope.yaml> F<n>`. A proof that passed last week may be fixed today.
2. Scope: the host is listed AND not excluded. Check path exclusions too: a host can be in scope with one
   endpoint excluded.
3. Class: it qualifies on this program (missing headers, versions, stack traces, user enumeration are real
   and almost never qualify).
4. Method: nothing the policy forbids produced the proof (scanner, volume, a third party's data).
5. Two accounts, both ours. The victim's data in the proof is data we planted.
6. The diff shows a difference AND the victim's marker. By design is ruled out by a with/without test.
7. Cache ruled out: replayed cold, other session.
8. Root cause not already submitted (below).
9. Severity justified metric by metric (skill `cvss-from-evidence`), never above what was proved.
10. Every step can be copied and run as written, from the first byte to the last. Platforms replay reports
    to the letter; a missing header fails the replay and closes the report.
11. No conditional wording, no data of a real customer, no secret in the text (skill `report-writing`).
12. A human has read the whole report. Unreviewed AI-written volume can get an account suspended.

## Root causes before variants
- Key each submitted finding by root cause: weakness class + component + mechanism. Keep it up to date
  before a hunt, not when writing.
- Several platforms pay a systemic issue on a decreasing scale (the source cites first report in full, second
  at half, third nothing: check the program's own rule). The same root cause on other hosts, endpoints or
  parameters is one group.
- Two open reports on a root cause: stop testing that lead. A fix resets the count.
- A hunter that returns a variant of an open root cause made a prioritisation error, not a finding.

## After a rejection
1. Read the exact reason: not applicable, out of scope, duplicate and informative are four different things.
2. "Cannot reproduce": add proof (the replay output, a second environment) before discussing.
3. "Theoretical": the impact is missing. Show it between our two accounts or drop it.
4. "Informative" on a low-impact finding: look for a chain (skill `chaining`), else close it.
5. Mediation last, with the proof attached.
6. Record the outcome on the board (planned: `bh outcome`), so the lineage learns.

## Never
- Submit automatically, or ask a platform for a deadline (MSRC: asking for an SLA loses eligibility).
- Accept a hunter's or a sub-agent's summary as the state of a finding. Take the best lead of each run and
  replay it yourself before it enters a report; never write a final summary on unverified findings.
- Resubmit a rejected finding reworded.

## Watch
- "CVE affects this version" is not "exploitable here": patched by backport, blocked upstream, or no public
  proof. A version match is a fact for the board, not a report.
- A low finding presented as critical costs the credibility of the next five reports.
