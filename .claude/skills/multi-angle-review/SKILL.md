---
name: multi-angle-review
description: Use when a plan, an architecture or a doctrine text must be challenged before work starts. Six reviewers with different angles in parallel, then one synthesis of agreements and contradictions.
---
Source: hermes/.archive/multi-perspective-audit/SKILL.md; merged from hermes/.archive/plan-audit-agency (no author or licence stated).
Modified: translated; the personas named after medical conditions replaced by the angle each one stood for; Hermes `delegate_task` replaced by our `claude -p` sub-agents.
Role: orchestrator, on the host. This is how the project's hostile reviews can be run again.

# Multi-angle review

## When
- A roadmap, a design, a brief or a doctrine change is about to be acted on.
- After a major rewrite: second round on what changed.

## The six angles
| Angle | Looks for | Answer format |
|---|---|---|
| Associative | edge cases, deadlocks, "what if X happens while Y" | one line per finding, problem or idea |
| Systematic | internal consistency, missing specifications, contradictions | section by section: ok, problem, contradiction |
| Adversarial | attack paths, leaks, what a hostile target or agent would do | per threat: path, impact, mitigation |
| Long-term | what breaks at ten times the scale, what the choice forecloses | free form, with numbers |
| Pragmatic | the smallest thing that delivers, what to drop | keep or drop, critical path |
| Inventive | ideas that are not in the documents | each idea must be new |

## Do
1. Give every reviewer the same complete material: the document, the files it refers to, the constraints
   (deadline, budget, the six rules that do not move). Its angle goes in the task line.
2. Launch in parallel, in two waves of three if concurrency is limited.
3. Consolidate, do not concatenate:
   - what all agree on;
   - where two reviewers contradict each other, and which evidence would settle it;
   - new ideas;
   - decisions to take, each as a question with a recommendation.
4. After the document changed, a second round: give the reviewers what changed and ask for what is still
   inconsistent.

## Never
- More than six reviewers: beyond that the answers repeat.
- A reviewer without the full material: it will invent the missing part.
- Let a reviewer's finding into the plan without checking it against the code or the document it cites.

## Watch
- Reviewers are sub-agents: their findings are claims. Each cited `file:line` is opened before it counts.
- Nothing from a target, and no secret, goes into a reviewer's material.
- The synthesis ends with what is left to the human, one decision per line.
