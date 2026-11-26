---
name: systematic-debugging
description: Use when a test fails, a segment misbehaves, the gate refuses something it should not, or a fix did not work. Root cause first, one hypothesis at a time, stop after three failed fixes.
---
Source: hermes/.archive/systematic-debugging/SKILL.md (author: Hermes Agent, adapted from obra/superpowers; licence: MIT).
Modified: condensed from 396 lines; Hermes tool names replaced by ours; examples from other projects and its reference files removed; the "In this repository" section is ours, from the README.
Role: harness developer.

# Systematic debugging

## The rule
No fix without a root cause. A symptom patched is a failure postponed. If phase 1 is not done, you cannot
propose a fix.

Use it most when it is tempting not to: under time pressure, when "one quick fix" looks obvious, after a
fix that did not work.

## Phase 1: root cause
0. Check the context: which branch, which worktree, which commit. Never assume the main branch.
1. Read the error fully: message, stack trace, line numbers, codes. It often names the cause.
2. Read the code before forming a theory. An error tells where, rarely why. Trace the value through the
   functions it crosses.
3. Reproduce reliably: exact steps, every time. Not reproducible = gather more data, do not guess.
4. What changed: recent commits, the diff, dependencies, configuration.
5. Several components (runner, agent, gate, judge, board): log what enters and leaves each boundary, run
   once, and let the evidence say where it breaks. Then investigate that component only.
6. Trace bad data back to where it was produced. Fix at the source.
Checkpoint: you can say why it happens. If not, stay in phase 1.

## Phase 2: pattern
- Find working code that does something close, in this repository. Read it completely.
- List every difference between working and broken, however small. Do not decide in advance that one
  cannot matter.
- Note what the broken part depends on: settings, environment, order of start.

## Phase 3: hypothesis
- One hypothesis, written: "X is the cause because Y".
- The smallest change that tests it. One variable.
- It worked: phase 4. It did not: a new hypothesis, never a second fix on top of the first.
- When you do not understand, say so. Do not pretend.

## Phase 4: fix
1. A failing test first, the simplest reproduction.
2. One change, at the root cause. No "while I am here".
3. The regression test, then the whole suite: `uv run pytest`.
4. The fix failed: count. Fewer than three attempts, back to phase 1 with what you learned. Three or more:
   stop and question the design, with the human, before a fourth.
Signs of a design problem: each fix reveals new coupling elsewhere, or creates a new symptom in another
place.

## Stop signs: back to phase 1
"Quick fix now, investigate later"; "just try changing X"; several changes at once; skipping the test;
"it is probably X" without having read the code; a fix proposed before the data flow is traced; "one more
attempt" after two.
When the human says stop or asks for the last good state: roll back at once, propose nothing, wait.

## In this repository
- After a change in the gate's policy module, restart the gate container: the proxy reloads only its addon
  file. Until then the gate refuses (fail-closed), which looks like a bug of your change.
- Recreate only the agent container, never the whole pod while the lab runs.
- The escape suite checks the reason of each refusal, not only that it was refused: a refusal for the wrong
  reason is a failure.
- A red test is never "a flaky runner" until it has been reproduced through the official command.
