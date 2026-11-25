---
name: ai-red-team-pyrit
description: Load when red-teaming an AI system (a Copilot, an LLM app or an agent we own an account on) or when planning, running or wrapping PyRIT, its attacks/orchestrators, converters, targets, scorers or memory, including multi-turn jailbreaks (Crescendo, PAIR, TAP) and indirect (cross-domain) prompt injection. Also load before deciding whether an AI "jailbreak" is a bounty-grade vulnerability, or before designing a `bh-pyrit` builtin.
---

# AI red teaming with PyRIT (MSRC / Copilot)

Source: MSRC webinar "Zero Day Quest - Learn to Red Team AI Systems Using PyRIT", recorded 2 Dec 2024
(YouTube `jq9DcEL3cHE`, 49 min). Speakers: an AI Red Team member (bounty program, bug bar) and the PyRIT
engineering lead. Quotes, positions and transcription errors: `references/talk-notes.md`.
Related skills: `msrc-ai-bug-bounty` (severity, what pays), `msrc-copilot-studio-research`.
Rules for the harness on MSRC: `docs/research/15-msrc-premier-programme.md`.

**Dating.** The talk shows PyRIT around v0.5 (late 2024). PyRIT has since moved from `Azure/PyRIT`
(archived) to **https://github.com/microsoft/PyRIT** (v1.2.1, 2026-11-18; names below checked on `main`
@ `066b4e7421`, 2026-11-25). v0.10.0 renamed orchestrators to "attacks" (executors). Each name below is
tagged **[talk]** (heard in the talk; the transcript is automatic, "Pirate" = PyRIT) and/or **[repo]**
(seen in the current repo). Anything untagged is my inference.

## 1. PyRIT concepts as presented

Five swappable "LEGO block" components [talk]; an attack wires them together.

| Component | Talk (2024) | Current repo (2026) |
|---|---|---|
| **Orchestrator** = attack strategy and logic; "the one component that's not an interface" | `PromptSendingOrchestrator` ("prompt sending orchestrator"), `CrescendoOrchestrator`; strategies named: PAIR, TAP, Crescendo, Skeleton Key, Flip attack [talk] | `PromptSendingAttack`, `CrescendoAttack`, `RedTeamingAttack`, `PAIRAttack`, `TAPAttack` / `TreeOfAttacksWithPruningAttack`, `SkeletonKeyAttack`, `ManyShotJailbreakAttack`, `MultiPromptSendingAttack` [repo]. Config objects `AttackAdversarialConfig`, `AttackScoringConfig`, `AttackConverterConfig`, runner `AttackExecutor` [repo]. `FlipAttack` is in the v0.10.0 rename list but not in the current `pyrit.executor.attack` exports (not checked further). |
| **Datasets** = the prompts / objectives | "seed prompts", "a couple hundred simple jailbreaks", jailbreak templates [talk] | `pyrit/datasets/jailbreak/text_jailbreak.py`, `TextJailbreakConverter` [repo] |
| **Converters** = transform a prompt (stackable) | Base64, Caesar, translation, image, audio; "emoji converters", "add image text converter", "ASCII smuggler converter", a translation converter, "rap battle" rewrite [talk] | `Base64Converter`, `CaesarConverter`, `TranslationConverter`, `EmojiConverter`, `AddImageTextConverter`, `AsciiSmugglerConverter`, `PDFConverter`, `WordDocConverter`, `VariationConverter`, `ToneConverter`, `LLMGenericTextConverter` [repo]. The class used for "rap battle" was not named; probably an LLM-backed converter (unverified). |
| **Targets** = what we talk to: an AI endpoint **or** a storage/channel the AI later reads | "OpenAI chat target" (GPT-4o), Hugging Face, Azure Blob storage, SharePoint site; a custom email target [talk] | `OpenAIChatTarget`, `HTTPTarget`, `AzureBlobStorageTarget`, `PlaywrightTarget`, `PlaywrightCopilotTarget` (consumer and M365 Copilot UI), `WebSocketCopilotTarget` (`wss://substrate.svc.cloud.microsoft/...`), `ClaudeChatTarget`, `TextTarget` [repo]. Targets accept `max_requests_per_minute` [repo]. |
| **Scorers** = was the attack successful / how toxic | "a common way to say was this attack successful"; often unnecessary when success is visible (exfil happened) [talk] | `SubStringScorer`, `RegexScorer`, `SelfAskTrueFalseScorer`, `SelfAskRefusalScorer`, `MarkdownInjectionScorer`, `SecretDisclosureScorer`, `SystemPromptExtractionScorer`, `MessageToolCallScorer`, `TrueFalseCompositeScorer` [repo] |
| **Memory** | **Not discussed in the talk.** | `SQLiteMemory` (replaced DuckDB in v0.10.0), `AzureSQLMemory`, `CentralMemory`; every run stored as an `AttackResult`; init via `from pyrit.setup import initialize_pyrit_async` [repo, v0.10.0 release notes] |

Crescendo parameters named in the talk: the objective target, "the adversarial chat", "our scoring
target", converters [talk]. Indirect injection: the 2024 `XPIAOrchestrator` is now `XPIAWorkflow`
(`attack_setup_target` plants the payload, a processing callback triggers the victim AI) [repo]; the talk
does not use the term XPIA.

## 2. Red-team method presented

1. **Find the scenario yourself.** PyRIT "won't help you come up with the attack or the scenario". It
   helps with the injection text, i.e. bypassing AI-specific mitigations (content filters, metaprompt,
   fine-tuning) [talk].
2. **Look at the integration, not the model.** How is the model API called, what functions are added on
   top, is there a human in the loop or a confirmation before an action? Treat the model as a black box
   and apply app-sec skills [talk, Q&A].
3. **Map untrusted input -> AI -> privileged output.** "Where you can enter prompts", where input lands
   and where output goes; a trusted/untrusted mix that someone acts on is "a really good place to dig" [talk].
4. **Assume injection is possible.** "Most of these systems will actually be vulnerable to prompt
   injections"; no single mitigation exists [talk]. The bounty question is the impact.
5. **Iterate cheaply on delivery, one change at a time** (the email-Copilot walkthrough) [talk]:
   plain prompt -> jailbreak templates -> payload as image attachment (`AddImageTextConverter`) -> PDF
   attachment -> ASCII smuggling -> other language (Spanish) -> style rewrite. Converters stack.
6. **Expect to write code.** The email target and the MSG-template converter "don't exist"; real
   scenarios need custom targets/converters [talk].
7. **Validate manually and keep notes** of hypotheses; ask `bounty@microsoft.com` when unsure [talk].

## 3. Workflow: testing a Copilot or agent we own

Preconditions (hard): two accounts/tenants that are ours (attacker A, victim B); program scope file
loaded; `automation_allowed` known; no Microsoft employee or third-party content involved.

1. **Inventory the surface** with `bh-browse` on B: every channel the AI reads (mail, files, web pages,
   calendar, chat history, plugins/connectors) and every action it can take (send mail, fetch URL,
   render markdown/images, write files, call tools). Write it as a table in notes.
2. **Pick a cross-boundary path**: content A controls -> read by B's Copilot -> action or disclosure
   visible to A. No path = no bounty; stop or change surface.
3. **Canary first.** Plant a benign instruction from A that asks B's AI to emit a unique token
   (`BH-CANARY-<id>`) or fetch a URL on an endpoint we own. Benign payloads only; the token proves
   instruction-following without harm.
4. **Trigger as B** with an ordinary user request ("summarize my last mail").
5. **Observe the side effect** in the gate HAR / OOB log / A's inbox, not in the model's prose.
6. **If blocked**, vary delivery with small converter stacks (step 2.5), a few prompts per variant,
   at the program rate. Record each variant and result.
7. **Escalate impact only on our own data**: replace the canary with B's own test secret (planted by us)
   and show it reaching A. Stop at proof of concept.
8. **Reproduce twice**, minimal steps, then hand to the judge. Report = screenshots, steps, PoC [talk].

## 4. What counts as a vulnerability (MSRC bounty sense)

Pays (per the talk; check `msrc-ai-bug-bounty` and the live AI bug bar):
- **Inference manipulation that crosses the user boundary**: an injection from user A changes what user
  B's AI does: data exfiltration, privilege escalation, manipulating another user's output [talk].
- **Data / RAG poisoning affecting other users**, model or training-data theft, inferring other users'
  inputs (the talk cites a packet-length side channel) [talk].
- Rate-limit bypass: report it, do not use it [talk].

Does not pay:
- Jailbreaks in your own session ("you don't get bounties for convincing Chat GPT to tell you how to make
  meth") [talk]. PyRIT's Molotov/meth examples are placeholders for your scenario objective.
- System prompt extraction, unless it holds user-specific confidential data [talk].
- Fine-tuning or poisoning only your own context [talk].
- Self-XSS-like issues with no way to reach another user: moderate at best [talk, by analogy].

Test: can I state the victim, what the attacker controlled, what crossed, and what the attacker gained
or changed? If one is missing, it is not a finding.

## 5. Limits and pitfalls

- **Volume.** MSRC forbids automated testing that "generates excessive traffic" and DoS; the talk asks
  to abide by rate limits with PyRIT specifically. Blasting "a couple hundred" jailbreaks at a
  production Copilot is the opposite. Small batches, program rate, stop on throttling.
- **Harm objectives.** Do not use PyRIT's harmful-content datasets as objectives against production
  services: no impact, policy risk, and it can trip our own model's refusals (blocker `refusal`).
- **Attacker LLM required** for Crescendo/PAIR/TAP, translation and style converters, and self-ask
  scorers; setting it up is "one of the biggest hurdles" [talk]. Speaker used GPT-4o; a 2026-09 PyRIT
  blog finds the attacker model changes success rates a lot (less-aligned models do better) [repo blog].
- **LLM scorers are not proof.** They can be fooled and can be injected by the target's reply. Prefer a
  deterministic oracle (canary substring, OOB hit, mail received).
- **API drift.** Code from the talk or old blogs (`*Orchestrator`, `initialize_pyrit`, DuckDB) does not
  run on v1.x. Read the repo docs for the installed version.
- **Copilot targets.** `WebSocketCopilotTarget` uses a websocket (the gate refuses websockets);
  `PlaywrightCopilotTarget` needs a logged-in browser page. Both automate a production service.
- **Transcript errors**: see `references/talk-notes.md` (names, URLs, "Integrity", "Garrick").
- PyRIT executes LLM output as data, but third-party code runs with our rights: pin the version.

## 6. Integrating with bull-harness (`bh-pyrit`, proposal)

Not built. Fits the existing builtin contract (`docs/architecture.md` §5): stdlib wrapper in
`src/bh/agent`, PyRIT installed in the agent image, no MCP.

**Shape.** `bh-pyrit <recipe> --as <identity> [--variants N]` where a recipe is a small YAML/JSON the agent
writes: target spec, payload text file, converter stack, oracle. Recipes, not free Python: the hooks
see one Bash command, the lock and program rules apply, and the judge can replay it.

**Traffic through the gate.**
- `HTTPTarget` (httpx) for API-shaped endpoints: proxy from env (`HTTPS_PROXY=gate:8080`) and the gate CA
  in `verify`/`SSL_CERT_FILE`. Cookies and required headers are injected by the gate from `--as`, never
  passed to PyRIT. Check that httpx honors the env proxy and CA in this setup before relying on it.
- Browser-only Copilots: custom target that drives the same proxied Chromium as `bh-browse`
  (`PlaywrightTarget` / `PlaywrightCopilotTarget` take a page). Not `WebSocketCopilotTarget` (websockets
  refused by the gate).
- Indirect injection: the "setup target" is a custom target that writes the payload through A's account
  (mail, file upload) via the gate; the "processing" step is B's ordinary request. Both identities ours.

**Rate.** Gate token bucket is the hard limit. Also set `max_requests_per_minute` on every target, cap
`--variants` (e.g. 10 per call) and the attempts per surface per run; a 429 or WAF challenge ends the
call. MSRC scopes have `scanners_allowed: false`: `bh-pyrit` must be classed as a test tool, and the
cap is what keeps it from being an automated scanner.

**Output.** <= 25 lines: recipe, variants sent, per-variant oracle result (hit/miss/refused/error),
first hit with its HAR flow id. Raw: `raw/pyrit/<id>/` with the SQLite memory (`SQLiteMemory(db_path=...)`),
each converted payload, responses, and `recipe.json` for replay. Endpoints touched go to
`endpoints.jsonl`; coverage to `coverage.json`.

**Which LLM generates attacks and scores?**
- **Default: none inside PyRIT.** The hunting agent (Claude, already on the relay) writes the payload
  text and chooses the converter stack. `bh-pyrit` only uses deterministic converters
  (`AsciiSmugglerConverter`, `Base64Converter`, `AddImageTextConverter`, `PDFConverter`, ...) and
  deterministic oracles (`SubStringScorer`/`RegexScorer` on the canary, gate/OOB evidence). Cost: zero
  extra relay requests; quota is the agent's normal turns. The judge replays `recipe.json`.
- **Not recommended: `ClaudeChatTarget(endpoint="http://gate:8081")`** as adversarial chat / scorer
  [repo: it takes `endpoint`]. Each Crescendo turn costs one adversarial call plus scoring calls; it
  draws on the segment's relay budget (`3 x max_turns + 30`) and the shared quota, which the
  architecture already lists as the nested-`claude -p` residual risk. LiteLLM headers and betas are
  untested against the relay's allowlist. Asking Claude to write jailbreaks for multi-turn harm
  objectives also risks refusals -> `refusal` blocker -> program parked (CVP Defense tier).
- **Third-party attacker model (OpenAI, Azure OpenAI, Grok...)**: never a key in the agent. Only via a
  second relay in the gate (key stays in the gate, host on the system allowlist, own budget), and only
  if multi-turn attacks prove necessary. Decision for Mio; out of v1.
- **Translation / style converters** need an LLM: in v1 the agent writes the translated or restyled text
  itself and passes it as the payload.

**Acceptance for a first version.** Against a local mock "assistant" we run (`bh target local`; to build,
it does not exist yet; `docs/research/12-injection-lab.md` attacks the hunter, not a target): a recipe
with a canary goes through the gate at the configured rate, the summary is <= 25 lines, the raw dir holds
the SQLite DB and the payloads, and the judge replays the recipe and sees the same oracle hit.

## 7. Verify before use

- PyRIT docs: https://github.com/microsoft/PyRIT (and the docs site linked from its README).
- v0.10.0 release notes for the orchestrator -> attack map and memory changes.
- Every class above against the version actually installed (`pip show pyrit`, then its exports).
