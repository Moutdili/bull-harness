---
name: swarm-handoff
description: Use when handing a lot of work to `claude -p` sub-agents (a wave of the roadmap), validating a parallel launch, or auditing what a swarm delivered. Preflight, brief, ownership, proof over reports.
---
Source: hermes/devops/claude-code-handoff/SKILL.md (author: Hermes Agent, licence: MIT); merged from hermes/software-development/writing-plans (Hermes Agent, adapted from obra/superpowers, MIT) and hermes/devops/kanban-orchestrator (no licence stated).
Modified: translated; bound to our lots, worktrees and audit container; Hermes sync scripts, plugin marketplace steps, game-project examples and the blanket permission-skip advice removed.
Role: orchestrator, on the host.

# Swarm handoff

## When
- You write the briefs of a wave, or launch lots in parallel.
- A swarm finished and you must say what is really done.

## Preflight: can the agent work at all?
1. The lot's worktree exists on the base commit; git identity is set; a commit lands.
2. Permissions: an agent that must ask for each command produces nothing. Give an allowlist by command
   family in the settings of the lot. Never a blanket bypass on the host.
3. Binaries reachable in a non-interactive shell (`uv`, `podman`, test runners).
4. The test command of the brief passes on the base commit before any change.
5. Proof of execution, not of compilation: decide which observable marker shows the new code really runs.

## The brief (one file per lot; no question should be needed)
1. Role and frame: what the project is, in ten lines; what is already done, with "do not redo".
2. Reading list: 4 or 5 files, in order. No exploration.
3. Items with binary acceptance criteria. Tasks small enough to verify one by one; exact file paths. If the
   executor has to guess, the brief is incomplete.
4. Files: owned (it may write) and forbidden (everything else). One owner per path; shared entry points
   belong to one lot only.
5. Contracts fixed across lots: function names, file layouts, formats. Not negotiable inside a lot.
6. Hard rules, numbered, checkable by a command where possible.
7. Environment that really exists: the tools installed, and an explicit "you do NOT have" list. Never name a
   binary that is absent: the agent will call it, fail and burn its budget.
8. Limits as ceilings, never as quotas. A volume target becomes a policy violation and rewards noise.
9. Tests to run, and the final report format (short, fixed fields, uncertainties last).
10. Cutoff: at about three quarters of the budget, stop starting things; commit and report.

## Validate a parallel launch (all four, or say which one breaks)
1. Disjoint zones: the ownership matrix is written before launch.
2. One worktree and one branch per agent; a merge order is decided.
3. Each lot has its own gate (tests) that passes where it will be merged, not only on a clean checkout.
4. No dependency on something another lot has not delivered; else it goes last.

## Audit a swarm: evidence, not statements
- A sub-agent's report is a self-declaration. Count the tests yourself on the merged tree; report only the
  number observed. A gap between announced and real invalidates the rest of the report.
- A diffstat is not a diff: on an old base it shows your recent files as deleted. Read the diff per file.
- Compare contracts after syncing the base, or every contract change looks like an out-of-scope edit.
- A stale gate does not describe the tree: rerun on the current head and say which run counts.
- Check merges by branch or commit, never by a path, and keep stderr visible.
- The end of a transcript is not the end of the work: compare commit dates and authors before attributing.
- Run the whole suite in the audit container (`tools/audit-exec.sh`) before each merge.

## Never
- Two agents on one file.
- More than eight lots in one wave, or any wave without an ownership matrix and a merge order: merging then costs more than it saves.
- Let documentation copy code: point to `file:line`.
- Blame the agent for a failure of the scaffold you gave it before reproducing the build yourself.
- Leave what you changed only in the chat: an agent reads files, so put it in a versioned note and check it
  is in the index, not just on disk.

## Watch
- First fifteen minutes: no first commit, no test run, or reading source instead of the reading list means
  the brief is not being followed. Stop and fix the brief.
- Installed skills are not used skills: count `Skill` tool calls in the transcript. Descriptions cost tokens
  every turn (the source measured about 14,000 tokens for 390 skills): install few.
