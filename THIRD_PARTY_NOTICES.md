# Third-party notices

bull-harness reuses code, text or ideas from the projects below. Each section names the licence, the repository
URL as the project's own `LICENSE` or README gives it (otherwise « à compléter par l'orchestrateur »), and the table of what
we took. The code tables are filled by the lot that copies the code (wave W3); a project with an empty table has given us
nothing yet. Rows marked « W3 » name files that lots A to H of wave W3 add: they were written from those lots' commits
and file headers, and were checked at the merge (2026-11-27): every path exists, and each file's header names its origin.

Obligation (Apache-2.0 §4, and good practice for every MIT source): each file we take from another project keeps that
project's copyright and licence notice, carries a prominent line saying that we modified it and what changed (« Modified
from <project> (<licence>) by bull-harness: <what changed> », or its `Source:` / `Modified:` lines for a skill), and has
its row below. A file without that line is refused at review.

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
| `src/bh/agent/hexstrike/registry.py` (W3, lot B) | `hexstrike_mcp.py` lines 267-5414 (`setup_mcp_server`, the 151 `@mcp.tool()` functions: names, categories, signatures copied verbatim); `hexstrike_server.py` lines 10377-15480 (the `/api/tools/*` routes: the command each ported tool sent) | rewritten as a data table; every tool classed (passive, mapper, scanner, local, no-route, refused); 27 tools ported to argv templates (one token per element, never a shell); help texts rewritten; defaults that pointed at missing wordlists or forbidden sources overridden; the free `additional_args` string becomes a checked token list. À préciser à la fusion. |
| `src/bh/agent/hexstrike/run.py` (W3, lot B) | `hexstrike_server.py` (command execution behind the `/api/tools/*` routes) | rewritten: no HTTP server, no Flask, no shell; each argument checked, then a subprocess with an argv list and a mandatory timeout; proxy and rate from the environment; full output under `raw/`, 25 lines returned; the three meta-tools `tools_list`, `tool_help`, `tool_run`. À préciser à la fusion. |
| `src/bh/agent/hexstrike/server.py`, `__init__.py` (W3, lot B) | `hexstrike_mcp.py` (the MCP client, FastMCP) | replaced by our own stdio MCP loop in the standard library, three meta-tools instead of 151 tools; started by `bh-agent mcp hexstrike`. À préciser à la fusion (own code with an origin note, or a modified file). |

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

All rows are W3 (lots C and H), checked at the merge. Each file names its Strix origin, the copyright line and
the licence in its header, and lists what it removed; the summary below is ours.

| fichier chez nous | fichier d'origine | modifications |
|---|---|---|
| `src/bh/skills/auth0/SKILL.md` | `strix/skills/technologies/auth0.md` | rewritten into our form; the tenant is a login host, never a target. Removed: callback-URL fuzzing, Management API and leaked machine credentials, user enumeration, MFA brute force, recovery-code guessing, password-grant logins, custom database scripts, secret searches in public repositories and CI logs, "Pro Tips". |
| `src/bh/skills/firebase/SKILL.md` | `strix/skills/technologies/firebase.md` | rewritten between our two identities; "Validation Requirements" became our Proof. Removed: anonymous sign-in and account creation, unauthenticated writes and uploads, ACL and IAM sweeps, bucket prefix listing, signed-URL guessing, calls toward metadata endpoints, blind enumeration, rules-review tooling, whitebox sections. |
| `src/bh/skills/function-level-authz/SKILL.md` | `strix/skills/vulnerabilities/broken_function_level_authorization.md` | rewritten between our two identities, proof standard of `broken-access-control`. Removed: internal services through SSRF, gRPC reflection, batch and alias tricks, identity headers overriding the session, approve and finalize retries on others' objects, cache-key confusion, "Pro Tips". |
| `src/bh/skills/jwt/SKILL.md` | `strix/skills/vulnerabilities/authentication_jwt.md` | rewritten on tokens of our own identities. Removed: "Tooling" (a tool we lack, its attack matrix, secret brute force), kid path traversal and key-lookup injection, attacker-hosted JWKS or x5u, remote key fetch toward internal hosts, refresh-token and mobile storage, token-theft chains, "Pro Tips". |
| `src/bh/skills/mass-assignment/SKILL.md` | `strix/skills/vulnerabilities/mass_assignment.md` | rewritten on our own objects only. Removed: ownership and tenant moves onto others' objects, systematic fuzzing with a field dictionary, race-and-reorder tricks, billing and credit changes, signup-time escalation, "Pro Tips". |
| `src/bh/skills/nextjs/SKILL.md` | `strix/skills/frameworks/nextjs.md` | rewritten between our two identities; "Validation Requirements" became our Proof and False positives. Removed: browser-console snippets, grepping bundles for secrets to use, image-optimizer requests toward internal hosts and DNS rebinding, RCE and DoS advisories as tests (kept as version facts), cache poisoning, revalidation triggering, runtime matrices. |
| `src/bh/skills/oauth-oidc/SKILL.md` | `strix/skills/protocols/oauth.md` | rewritten for our two identities and an in-scope authorization server. Removed: redirect_uri fuzz matrices, client enumeration from public repositories, dynamic client registration, device-code guessing, Referer harvesting from an attacker page, mobile scheme hijacking, "Tooling", "Pro Tips". |
| `src/bh/skills/postmessage/SKILL.md` | `strix/skills/vulnerabilities/browser_security.md` (sections "postMessage and Window Relationships", "Validation", "False Positives") | only the postMessage part kept, rewritten. Removed: monkey-patching in a controlled browser, XS-Leaks timing, service-worker and cache poisoning, worker capabilities, oversized URL and header tests, local-network access, gadget harnesses, cross-browser matrices. |
| `src/bh/skills/prototype-pollution/SKILL.md` | `strix/skills/vulnerabilities/prototype_pollution.md` | rewritten; server-side pollution limited to the lab or written permission. Removed: server-side code-execution gadget chains, command and require payloads, auth-flag pollution, denial-of-service effects, filter and WAF bypass lists, "Tooling", "Pro Tips". |
| `src/bh/skills/race-condition/SKILL.md` | `strix/skills/vulnerabilities/race_conditions.md` | rewritten for our two identities and two requests. Removed: bursts and ramping parallelism, last-byte synchronisation tooling, spreading over IPs, sessions or accounts, degrading the target, rate-limit and quota bypass, retry storms, cross-service sagas, "Pro Tips". |
| `src/bh/skills/request-smuggling/SKILL.md` | `strix/skills/vulnerabilities/http_request_smuggling.md` | lab only, detection by a request the back end waits on. Removed: differential confirmation by rapid identical requests, smuggled requests to restricted paths, capture of another user's request, cache poisoning through desync, header obfuscation lists, HTTP/2 downgrade tooling. |
| `src/bh/skills/ssti/SKILL.md` | `strix/skills/vulnerabilities/ssti.md` | rewritten; kept: the probe table, the evaluation vs reflection line, the false positives. Removed: every sandbox escape, class walk, reflection gadget and command-execution payload, object-access probes, out-of-band and sleep validation, file writes. |
| `src/bh/skills/subdomain-takeover/SKILL.md` | `strix/skills/vulnerabilities/subdomain_takeover.md` | rewritten; the hunter only observes. Removed: the enumeration pipeline and its tools, resolver sweeps, claiming the resource, alternate-domain and NS delegation takeover, certificate issuance, cache poisoning after takeover, the web-search step, "Pro Tips". |
| `src/bh/skills/csrf/SKILL.md` | `strix/skills/vulnerabilities/csrf.md` ("False Positives" only) | its false-positive lines rewritten into ours, marked "(Strix)"; the rest of the skill comes from Hermes skills with no licence stated. |
| `src/bh/skills/nosql-injection/SKILL.md` | `strix/skills/vulnerabilities/nosql_injection.md` ("False Positives" only) | four lines condensed into three, marked "(Strix)". |
| `src/bh/skills/supabase/SKILL.md` | `strix/skills/technologies/supabase.md` ("API Keys and Signing Keys", "Auth & Tokens" notes) | two false-positive lines taken and reworded, marked "(Strix)". |
| `src/bh/skills/xxe/SKILL.md` | `strix/skills/vulnerabilities/xxe.md` ("False Positives" only) | four lines reworded, network access dropped, marked "(Strix)". |
| `src/bh/skills/graphql/SKILL.md` | `strix/skills/protocols/graphql.md` | condensed and rewritten for two identities of ours, merged with our card `src/bh/cards/graphql.md`. Removed: alias enumeration of ids, array batching to pass limits, fragment bombs and other complexity tests, filter evasion, transport and timing tricks, persisted-query hash guessing. |
| `src/bh/skills/report-writing/SKILL.md` | `strix/skills/analysis/counterevidence.md`, `strix/skills/analysis/severity_calibration.md` | merged and condensed with the audit's report-writing skill (Hermes, below); Strix's tools mapped to ours. Removed: static-only findings without a replay, CVSS vector mechanics, severity examples aimed at internal services. |

`src/bh/skills/multi-tenant/SKILL.md` (W3, lot H) is our own text: its ideas were checked against the tenant sections of
four Strix skills, none copied, so it has no row.

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
| `src/bh/skills/report-writing/SKILL.md` (W3, lot C) | `../inputs/skills-audit/skills/report-writing/SKILL.md`, itself from hermes/creative/bug-bounty-report-triptyque (author: Hermes Agent, licence: MIT), merged there with Hermes sources with no licence stated; merged here with two Strix files (above). | merged and condensed; Strix's tools mapped to ours; nothing removed beyond the audit skill's own removals (the "anti-AI score" goal, cookie-stealing examples, report templates holding tokens). |
| `src/bh/skills/wordpress-rest/SKILL.md` (W3, lot H) | hermes/.archive/wordpress-security-audit/SKILL.md; merged from hermes/security/bug-bounty-workflow-automation/references/wordpress-api-recon.md and section titles of hermes/security/bug-bounty-hacking (Hermes Agent, MIT) (the other two: no author or licence stated). | translated; DNS lookups, GitHub searches, login pages, 100-record reads and real target names removed; minimal-read and stop rules are ours. |
| `.claude/skills/token-cost-of-commands/SKILL.md` | hermes/token-efficient-agent-commands/SKILL.md (author: Hermes Agent, licence: MIT). | translated; token counts measured on other models' tokenizers removed (they do not transfer); the non-ASCII one-character names and the Hermes plugin steps removed; the audit argument and the "In this repository" section are ours. Its probe script and reference were not repatriated. |

## obra/superpowers

- Licence: MIT, as the `Source:` lines state (Hermes Agent adapted these sources from obra/superpowers). No
  repository URL is given in these files.
- Wave W3: no skill of the sandbox (`src/bh/skills/`) comes from it, as the headers of lots C and H say
  (checked at the merge: no skill names it).

| skill chez nous | source | modifications |
|---|---|---|
| `.claude/skills/swarm-handoff/SKILL.md` | hermes/devops/claude-code-handoff/SKILL.md (author: Hermes Agent, licence: MIT); merged from hermes/software-development/writing-plans (Hermes Agent, adapted from obra/superpowers, MIT) and hermes/devops/kanban-orchestrator (no licence stated). | translated; bound to our lots, worktrees and audit container; Hermes sync scripts, plugin marketplace steps, game-project examples and the blanket permission-skip advice removed. |
| `.claude/skills/subagent-review-gates/SKILL.md` | hermes/software-development/subagent-driven-development/SKILL.md (author: Hermes Agent, adapted from obra/superpowers; licence: MIT) and its references context-budget-discipline.md and gates-taxonomy.md (adapted from gsd-build/get-shit-done, MIT © 2025 Lex Christopherson); merged from hermes/devops/sdlc-review (Jakub Wolniewicz (@frizikk) + Hermes Agent, MIT). | translated in part; Hermes `delegate_task` and kanban calls replaced by our `claude -p` lots; examples removed. |
| `.claude/skills/systematic-debugging/SKILL.md` | hermes/.archive/systematic-debugging/SKILL.md (author: Hermes Agent, adapted from obra/superpowers; licence: MIT). | condensed from 396 lines; Hermes tool names replaced by ours; examples from other projects and its reference files removed; the "In this repository" section is ours, from the README. |

## gsd-build/get-shit-done

- Licence: MIT, © 2025 Lex Christopherson, as the `Source:` line states (references `context-budget-discipline.md`
  and `gates-taxonomy.md`, adapted by Hermes Agent). No repository URL is given in these files.
- Wave W3: no skill of the sandbox (`src/bh/skills/`) comes from it, as the headers of lots C and H say
  (checked at the merge: no skill names it).

| skill chez nous | source | modifications |
|---|---|---|
| `.claude/skills/subagent-review-gates/SKILL.md` | hermes/software-development/subagent-driven-development/SKILL.md (author: Hermes Agent, adapted from obra/superpowers; licence: MIT) and its references context-budget-discipline.md and gates-taxonomy.md (adapted from gsd-build/get-shit-done, MIT © 2025 Lex Christopherson); merged from hermes/devops/sdlc-review (Jakub Wolniewicz (@frizikk) + Hermes Agent, MIT). | translated in part; Hermes `delegate_task` and kanban calls replaced by our `claude -p` lots; examples removed. |

## Not copied

Rien n'est copié de CAI (licence de recherche non commerciale) ni de Shannon (AGPL-3.0) : idées seulement.

Nothing is copied from CAI (non-commercial research licence) or Shannon (AGPL-3.0): ideas only. A file that would
copy either one is refused at review.
