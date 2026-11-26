# Third-party notices

bull-harness reuses code, text or ideas from the projects below. Each section names the licence, the repository
URL as the project's own `LICENSE` or README gives it (otherwise « à compléter par l'orchestrateur »), and the table of what
we took. The code tables are filled by the lot that copies the code (wave W3); a project with an empty table has given us
nothing yet.

## PentAGI

- Licence: MIT.
- Repository: à compléter par l'orchestrateur.
- Licence text: à compléter par l'orchestrateur (copy the project's `LICENSE` file verbatim here, with its copyright
  line, before the first file is copied).

| fichier chez nous | fichier d'origine | modifications |
|---|---|---|

## HexStrike AI

- Licence: MIT.
- Repository: https://github.com/0x4m4/hexstrike-ai (from its README).
- Licence text, as in its `LICENSE` file:

```
MIT License

Copyright (c) 2026 Muhammad Osama (0x4m4) <contact@0x4m4.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

| fichier chez nous | fichier d'origine | modifications |
|---|---|---|

## PentestGPT

- Licence: MIT.
- Repository: à compléter par l'orchestrateur.
- Licence text: à compléter par l'orchestrateur (copy the project's `LICENSE` file verbatim here, with its copyright
  line, before the first file is copied).

| fichier chez nous | fichier d'origine | modifications |
|---|---|---|

## Strix

- Licence: Apache License, Version 2.0 (http://www.apache.org/licenses/), copyright line in its `LICENSE`:
  « Copyright 2025 OmniSecure Inc. ».
- Repository: https://github.com/usestrix/strix (from its README).
- Licence text: the full Apache-2.0 text of its `LICENSE` file (the project ships no `NOTICE` file); a copy goes
  next to the first file we take from it.
- Apache-2.0 §4: every file taken from Strix keeps its copyright and licence notices, and **must carry a prominent
  notice that we modified it** (for instance a header line « Modified from Strix (Apache-2.0) by bull-harness:
  <what changed> »), and is listed below.

| fichier chez nous | fichier d'origine | modifications |
|---|---|---|

## Hermes Agent

- Licence: MIT, as the `Source:` lines of the skills below state (author: Hermes Agent; `claude-p-headless`:
  Hermes Agent + Teknium). No repository URL is given in these files.
- `subagent-review-gates` also merges `sdlc-review`, by Jakub Wolniewicz and Hermes Agent, MIT.
- Skills of `.claude/skills/` whose `Source:` line states no author or licence (`pre-submit-review`,
  `multi-angle-review`, `cvss-from-evidence`) are Mio's own skills and are not listed here.

| skill chez nous | source | modifications |
|---|---|---|
| `.claude/skills/report-writing/SKILL.md` | hermes/creative/bug-bounty-report-triptyque/SKILL.md (author: Hermes Agent, licence: MIT); merged from hermes/security/agent-de-conformite, hermes/bug-bounty/bug-bounty-proof-package, hermes/security/bug-bounty-methodology and hermes/security/live-recon/references/poc-format-mio.md (no licence stated). | translated; the "anti-AI score" goal, examples that steal cookies or list thousands of real users, HTML and server PoCs, and report templates holding tokens removed; title rule set to ours. |
| `.claude/skills/swarm-handoff/SKILL.md` | hermes/devops/claude-code-handoff/SKILL.md (author: Hermes Agent, licence: MIT); merged from hermes/software-development/writing-plans (Hermes Agent, adapted from obra/superpowers, MIT) and hermes/devops/kanban-orchestrator (no licence stated). | translated; bound to our lots, worktrees and audit container; Hermes sync scripts, plugin marketplace steps, game-project examples and the blanket permission-skip advice removed. |
| `.claude/skills/subagent-review-gates/SKILL.md` | hermes/software-development/subagent-driven-development/SKILL.md (author: Hermes Agent, adapted from obra/superpowers; licence: MIT) and its references context-budget-discipline.md and gates-taxonomy.md (adapted from gsd-build/get-shit-done, MIT © 2025 Lex Christopherson); merged from hermes/devops/sdlc-review (Jakub Wolniewicz (@frizikk) + Hermes Agent, MIT). | translated in part; Hermes `delegate_task` and kanban calls replaced by our `claude -p` lots; examples removed. |
| `.claude/skills/program-triage/SKILL.md` | hermes/pentest/bounty-target-selection/SKILL.md; merged from hermes/security/bug-bounty-methodology/references/rapid-multi-program-triage.md, hermes/pentest/pentest-workflow, hermes/arsenal-cavaliers, hermes/.archive/dev-human-patterns and hermes/web/blocked-page-recovery (Hermes Agent, MIT) (the others: no author or licence stated). | translated; bounty figures and tier lists that cannot be checked removed; harness readiness criteria are ours; third-party intelligence and any scan of a candidate removed. |
| `.claude/skills/third-party-repo-vetting/SKILL.md` | hermes/software-development/repo-due-diligence/SKILL.md (author: Hermes Agent, licence: MIT). | translated; output rules written for a chat channel removed; run location set to our audit container; the licence and notices step is ours. Its reference files (command block, supply-chain checklist, output template) were not repatriated. |
| `.claude/skills/vision-sessions/SKILL.md` | hermes/planner/deep-tech-vision-sessions/SKILL.md (author: Hermes Agent, licence: MIT). | translated; its one reference (a design note of another project) not repatriated. |
| `.claude/skills/systematic-debugging/SKILL.md` | hermes/.archive/systematic-debugging/SKILL.md (author: Hermes Agent, adapted from obra/superpowers; licence: MIT). | condensed from 396 lines; Hermes tool names replaced by ours; examples from other projects and its reference files removed; the "In this repository" section is ours, from the README. |
| `.claude/skills/compose-podman-parity/SKILL.md` | hermes/devops/compose-ci-parity/SKILL.md (author: Hermes Agent, licence: MIT). | translated; examples of another project's toolchain removed; kept as is otherwise. Our stack is rootless Podman with podman-compose, and the compose file must stay compatible with docker compose. |
| `.claude/skills/podman-disk-reclaim/SKILL.md` | hermes/devops/disk-space-reclamation/SKILL.md (author: Hermes, licence: MIT). | translated; paths of another machine removed; its helper script was not repatriated; the "In this repository" lines are ours. |
| `.claude/skills/claude-p-headless/SKILL.md` | hermes/.archive/claude-code/SKILL.md (author: Hermes Agent + Teknium, licence: MIT); merged from hermes/devops/claude-code-handoff (Hermes Agent, MIT). | translated in part; interactive tmux driving, dialog handling, permission-bypass recipes, local documentation paths of another project and installation steps removed. |
| `.claude/skills/token-cost-of-commands/SKILL.md` | hermes/token-efficient-agent-commands/SKILL.md (author: Hermes Agent, licence: MIT). | translated; token counts measured on other models' tokenizers removed (they do not transfer); the non-ASCII one-character names and the Hermes plugin steps removed; the audit argument and the "In this repository" section are ours. Its probe script and reference were not repatriated. |

## obra/superpowers

- Licence: MIT, as the `Source:` lines state (Hermes Agent adapted these sources from obra/superpowers). No
  repository URL is given in these files.

| skill chez nous | source | modifications |
|---|---|---|
| `.claude/skills/swarm-handoff/SKILL.md` | hermes/devops/claude-code-handoff/SKILL.md (author: Hermes Agent, licence: MIT); merged from hermes/software-development/writing-plans (Hermes Agent, adapted from obra/superpowers, MIT) and hermes/devops/kanban-orchestrator (no licence stated). | translated; bound to our lots, worktrees and audit container; Hermes sync scripts, plugin marketplace steps, game-project examples and the blanket permission-skip advice removed. |
| `.claude/skills/subagent-review-gates/SKILL.md` | hermes/software-development/subagent-driven-development/SKILL.md (author: Hermes Agent, adapted from obra/superpowers; licence: MIT) and its references context-budget-discipline.md and gates-taxonomy.md (adapted from gsd-build/get-shit-done, MIT © 2025 Lex Christopherson); merged from hermes/devops/sdlc-review (Jakub Wolniewicz (@frizikk) + Hermes Agent, MIT). | translated in part; Hermes `delegate_task` and kanban calls replaced by our `claude -p` lots; examples removed. |
| `.claude/skills/systematic-debugging/SKILL.md` | hermes/.archive/systematic-debugging/SKILL.md (author: Hermes Agent, adapted from obra/superpowers; licence: MIT). | condensed from 396 lines; Hermes tool names replaced by ours; examples from other projects and its reference files removed; the "In this repository" section is ours, from the README. |

## gsd-build/get-shit-done

- Licence: MIT, © 2025 Lex Christopherson, as the `Source:` line states (references `context-budget-discipline.md`
  and `gates-taxonomy.md`, adapted by Hermes Agent). No repository URL is given in these files.

| skill chez nous | source | modifications |
|---|---|---|
| `.claude/skills/subagent-review-gates/SKILL.md` | hermes/software-development/subagent-driven-development/SKILL.md (author: Hermes Agent, adapted from obra/superpowers; licence: MIT) and its references context-budget-discipline.md and gates-taxonomy.md (adapted from gsd-build/get-shit-done, MIT © 2025 Lex Christopherson); merged from hermes/devops/sdlc-review (Jakub Wolniewicz (@frizikk) + Hermes Agent, MIT). | translated in part; Hermes `delegate_task` and kanban calls replaced by our `claude -p` lots; examples removed. |

## Not copied

Rien n'est copié de CAI (licence de recherche non commerciale) ni de Shannon (AGPL-3.0) : idées seulement.

Nothing is copied from CAI (non-commercial research licence) or Shannon (AGPL-3.0): ideas only. A file that would
copy either one is refused at review.
