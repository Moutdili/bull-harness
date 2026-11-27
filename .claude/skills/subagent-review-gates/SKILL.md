---
name: subagent-review-gates
description: Use when executing a plan through sub-agents and reviewing what each returns. Fresh agent per task, two-stage review, named gates with a bounded retry, and a lean orchestrator context.
---
Source: hermes/software-development/subagent-driven-development/SKILL.md (author: Hermes Agent, adapted from obra/superpowers; licence: MIT) and its references context-budget-discipline.md and gates-taxonomy.md (adapted from gsd-build/get-shit-done, MIT © 2025 Lex Christopherson); merged from hermes/devops/sdlc-review (Jakub Wolniewicz (@frizikk) + Hermes Agent, MIT).
Modified: translated in part; Hermes `delegate_task` and kanban calls replaced by our `claude -p` lots; examples removed.
Role: orchestrator, on the host. Also a reading for the judge: the review lenses.

# Sub-agents: dispatch, review, gates

## When
You hold a plan (a brief per lot, skill `swarm-handoff`) and run it task by task.

## Do
1. Read the plan once. Give each sub-agent the full text of its task and the context it needs; do not make it
   read the whole plan, and do not paste large files into its prompt: name the paths.
2. One fresh sub-agent per task. Accumulated context causes confusion; a new one starts clean.
3. Two reviews, by two other fresh agents, in this order:
   - specification: every requirement implemented? paths and signatures as specified? nothing extra?
     Answer `PASS` or the list of gaps;
   - quality, only once the specification passes: conventions, error handling, tests that test the thing,
     no obvious bug. Answer `APPROVED` or `REQUEST_CHANGES` with critical, important, minor.
4. A different lens at each review round, so the third round does not re-find what the first found:
   | Round | Lens | How |
   |---|---|---|
   | 1 | artefact | read the diff cold, before the author's summary; then compare with the summary |
   | 2 | execution | run it: build, tests, the behaviour claimed |
   | 3+ | contract | re-read the original task and criteria; check every earlier request landed |
5. Ask each sub-agent to restate concrete facts in its answer ("the test fails without the fix"). Restated
   facts are evidence; "handled appropriately" is not.

## Gates: name each checkpoint and what happens when it fails
| Gate | Purpose | On failure |
|---|---|---|
| Pre-flight | preconditions before starting | block, nothing is created; fix and retry |
| Revision | output quality | loop back with precise feedback, 3 rounds at most; escalate earlier if the issue count does not go down |
| Escalation | what cannot be resolved | pause, present options to the human, never pick a default |
| Abort | prevent damage or waste | stop, keep state, say why |
For each gate write: what triggers it, what happens on failure, who resumes and from where.

## Keep the orchestrator's context lean
| Used | Behaviour |
|---|---|
| up to 30 % | full operation |
| 30 to 50 % | read verdicts and summaries rather than bodies; delegate |
| 50 to 70 % | economise; warn the human |
| above 70 % | checkpoint now, finish the current task, stop cleanly |
Early signs, before any threshold: a task declared done but incomplete; vague wording replacing specifics;
protocol steps skipped (five of eight criteria reported).

## Never
- Do the task yourself when the review fails: send it back with the gap.
- Start the quality review before the specification passes.
- Loop a revision forever.
- Take "tests pass" for "the right thing was built": that is what the specification review is for.

## Watch
- The orchestrator can check structure (a file exists, a test passes), not meaning. Meaning needs a run or a
  second fresh reader.
- A reviewer that read the author's summary first inherits its framing.
