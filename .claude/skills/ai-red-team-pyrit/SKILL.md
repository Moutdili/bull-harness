---
name: ai-red-team-pyrit
description: Load when red-teaming an AI system (a Copilot, an LLM app or an agent we own an account on) through indirect (cross-domain) prompt injection between two of our accounts, when choosing payload delivery (converters: Base64, Unicode tags, text in image, PDF), or when planning, wrapping or rejecting PyRIT (attacks/orchestrators, converters, targets, scorers, memory) for bull-harness. Whether a finding pays is decided by `msrc-ai-bug-bounty`.
---

# AI red teaming with PyRIT (MSRC / Copilot)

Source: MSRC webinar "Zero Day Quest - Learn to Red Team AI Systems Using PyRIT", recorded 2 Dec 2024
(YouTube `jq9DcEL3cHE`, 49 min). Speakers: an AI Red Team member (bounty program, bug bar) and the PyRIT
engineering lead. Quotes, positions and transcription errors: `references/talk-notes.md`.
Related skills: **`msrc-ai-bug-bounty`** owns what pays, severity and the report format (§6 there);
`msrc-copilot-studio-research` owns the Copilot Studio / Power Platform surface.
Rules for the harness on MSRC: `docs/research/15-msrc-premier-programme.md`.
Canary name in all three skills: `BH-CANARY-<id>`.

**Dating.** The talk shows PyRIT around v0.5 (late 2024). PyRIT has since moved from `Azure/PyRIT`
(archived) to **https://github.com/microsoft/PyRIT** (v1.2.1, 2026-11-18; names below checked on `main`
@ `066b4e7421`, 2026-11-25, not re-checked since). v0.10.0 renamed orchestrators to "attacks" (executors).
Tags: **[talk]** = heard in the talk (automatic transcript, "Pirate" = PyRIT); **[repo]** = seen in the
current repo; **[inferred]** = ours. Class spellings for things only *spoken* in the talk are [inferred].

**Decision for v1: no PyRIT** (§6). The concepts below stay useful as vocabulary and as a later option.

## 1. PyRIT concepts as presented

Five swappable components: "Each are LEGO block interfaces that can be swapped out" [talk]; an attack wires them.

| Component | Talk (2024) | Current repo (2026) |
|---|---|---|
| **Orchestrator** = attack strategy; "they're the one component that that's not an interface" [talk] | spoken: "prompt sending orchestrator", "a Crescendo orchestrator"; strategies named: PAIR, TAP, Crescendo, Skeleton Key, Flip attack [talk]. Class spellings `PromptSendingOrchestrator`, `CrescendoOrchestrator` [inferred, match the v0.10.0 rename list] | `PromptSendingAttack`, `CrescendoAttack`, `RedTeamingAttack`, `PAIRAttack`, `TAPAttack` / `TreeOfAttacksWithPruningAttack`, `SkeletonKeyAttack`, `ManyShotJailbreakAttack`, `MultiPromptSendingAttack`; `AttackAdversarialConfig`, `AttackScoringConfig`, `AttackConverterConfig`, `AttackExecutor` [repo]. `FlipAttack` not in current exports (not checked further). |
| **Datasets** = prompts / objectives | "seed prompts", "a couple hundred simple jailbreaks" [talk] | `pyrit/datasets/jailbreak/text_jailbreak.py`, `TextJailbreakConverter` [repo]. **Excluded from our recipes** (§5). |
| **Converters** = transform a prompt (stackable) | Base64, Caesar, translation, image, audio; "emoji converters", "add image text converter", "ASCII smuggler converter", "rap battle" [talk] | `Base64Converter`, `CaesarConverter`, `TranslationConverter`, `EmojiConverter`, `AddImageTextConverter`, `AsciiSmugglerConverter`, `PDFConverter`, `WordDocConverter`, `VariationConverter`, `ToneConverter`, `LLMGenericTextConverter` [repo]. "Rap battle" used an LLM on the back end [talk]; class not named. |
| **Targets** = an AI endpoint **or** a storage/channel the AI later reads | "OpenAI chat target" (GPT-4o), Azure Blob storage, SharePoint; a custom email target "which doesn't exist" [talk] | `OpenAIChatTarget`, `HTTPTarget`, `AzureBlobStorageTarget`, `PlaywrightTarget`, `PlaywrightCopilotTarget`, `WebSocketCopilotTarget` (`wss://substrate.svc.cloud.microsoft/...`), `ClaudeChatTarget`, `TextTarget`; `max_requests_per_minute` [repo]. |
| **Scorers** = success / toxicity | "a common way to say like was this attack successful or how toxic is this content"; often unneeded: "you can kind of just see if it worked based on exfiltrating data" [talk] | `SubStringScorer`, `RegexScorer`, `SelfAskTrueFalseScorer`, `SelfAskRefusalScorer`, `MarkdownInjectionScorer`, ... [repo] |
| **Memory** | **Not discussed in the talk.** | `SQLiteMemory` (replaced DuckDB in v0.10.0), `AzureSQLMemory`, `CentralMemory` [repo] |

Crescendo inputs named in the talk: "a target", "the adversarial chat, our scoring target", converters
[talk]. Indirect injection: the 2024 `XPIAOrchestrator` is now `XPIAWorkflow` [repo]; the talk does not
use the term XPIA.

## 2. Red-team method presented

1. **Find the scenario yourself.** "Pirate won't help you come up with the attack or the scenario you're
   trying to do" [talk]. It helps with delivery past AI-specific mitigations (content filters, metaprompt,
   fine-tuning).
2. **Look at the integration, not the model.** "I always look at the integration"; "Do we have, for
   example, human in the loop?"; "you can sort of see the AI as a black box" [talk].
3. **Map untrusted input -> AI -> privileged output.** Trusted/untrusted mix that someone uses: "that's
   that's a really good place to to dig" [talk].
4. **Assume injection is possible.** "Most of these systems will actually be vulnerable to prompt
   injections" [talk]. The bounty question is the impact on another user.
5. **Iterate cheaply on delivery, one change at a time** (the email-Copilot walkthrough) [talk]:
   plain prompt -> payload as image attachment -> PDF attachment -> ASCII smuggling -> other language ->
   style rewrite. Converters stack. (The talk also tries the jailbreak dataset first: excluded here, §5.)
6. **Expect to write code**: the email target and the MSG-template converter "don't exist" [talk].
7. **Validate manually and keep notes** [talk]; ask `bounty@microsoft.com` when unsure.

## 3. Workflow: indirect injection between two accounts we own

Preconditions (hard):
- Two accounts/tenants that are ours (attacker A, victim B): "create two users uh that you holy control"
  [talk] ("holy" = wholly). Program scope loaded; `automation_allowed` known.
- No Microsoft employee, partner, vendor or third-party content involved [talk, doc 15].
- Use the services "in a way that does not violate our service agreements" [talk]; a throttled or
  challenged test account ends the run on that surface.
- Stop rules of §5 known (server-side execution, third-party data).
- Target UI transport measured (websocket or HTTP, §6). Websocket-only: blocker, stop.

Steps [inferred, from the talk's method]:
1. **Inventory the surface** as B: every channel the AI reads (mail, files, web pages, calendar, chat
   history, plugins/connectors) and every action it can take (send mail, fetch URL, render markdown or
   images, write files, call tools). Table in notes.
2. **Pick a cross-boundary path**: content A controls -> read by B's AI -> action in B or B's data
   visible to A. No path = no bounty; stop or change surface. Mail or file injection supposes an AI that
   reads B's mailbox or drive, probably behind a licence [inferred]: if so, blocker `paid`.
3. **Canary first.** A plants a benign instruction asking B's AI to emit `BH-CANARY-<id>` somewhere **A
   can read** (a reply mail to A, a shared file, a comment on A's object), or to perform a harmless action
   in B. Benign payloads only.
4. **Trigger as B** with an ordinary request ("summarize my last mail").
5. **Observe the side effect**, never the model's prose: A's inbox or object (as A), B's state (as B), the
   gate HAR. No receiver of ours exists (`bh-oob`, issue 31 open): a proof that needs one = blocker
   `oob-needed`. Off-host requests from B's browser are counted per host by `bh-browse` (lead only).
6. **Control**: same request by B without the poisoned source, and same content without the payload.
   Both must not show the canary or the action.
7. **If blocked**, vary delivery with small converter stacks (step 2.5), a few variants, at the program rate.
8. **Escalate impact only on our own data**: replace the canary with B's own test secret (planted by us)
   and show it reaching A. Stop at proof of concept.
9. **Repeat N times, report k/N** and the conversation IDs (`msrc-ai-bug-bounty` §6), then hand to the judge.

## 4. What counts

Pays / does not pay, severity: **`msrc-ai-bug-bounty` §1-§4** only. One check before calling it a finding:
can I state the victim (B), what A controlled, what crossed, and what A gained or changed? If one is
missing, it is not a finding. Rate-limit bypass: not hunted (`msrc-ai-bug-bounty` §3).

## 5. Limits, stop rules, pitfalls

- **Server-side execution** (traditional bug or one of the AI categories): stop at the first proof.
  "reach out to bounty@microsoft.com if you want additional guidance on should you proceed uh or not" ...
  "you don't go beyond proof of concept" [talk]. Harness gesture: `bh-note blocked other "server-side
  execution: <where>, stopped at PoC"`, leave the lead; Mio decides whether to write to MSRC.
- **Third-party data seen by accident**: stop, no re-read, `bh-note blocked other "third-party data seen:
  <where, no content>"`; see `msrc-copilot-studio-research` §6.
- **Volume.** MSRC forbids automated testing that "generates excessive traffic" and DoS [doc 15]; the talk
  admits the tool if you "abide by the rate limiting that is in place" [talk]. Small batches, program rate,
  stop on throttling.
- **No jailbreak material.** No harmful-content objectives, no jailbreak dataset, no `TextJailbreakConverter`,
  no DAN-style templates against production: no impact, policy risk, and our own model may refuse
  (blocker `refusal`, CVP Defense tier).
- **Attacker LLM required** for Crescendo/PAIR/TAP, translation and style converters, self-ask scorers:
  "you need to have a generative AI endpoint that you're using for your infrastructure" [talk]. Speaker used
  GPT-4o; a 2026-09 PyRIT blog finds the attacker model changes success rates a lot [repo blog].
- **LLM scorers are not proof.** They can be fooled or injected by the target's reply. Deterministic oracle
  only (canary substring, state change, mail received).
- **API drift.** Code from the talk or old blogs (`*Orchestrator`, `initialize_pyrit`, DuckDB) does not
  run on v1.x.
- **Third-party code** runs with our rights: pin any version we install.
- **Transcript errors**: `references/talk-notes.md`.

## 6. Integrating with bull-harness (proposal, not built)

**Blocking point: the transport.** The gate refuses every websocket upgrade (`src/bh/gate/addon.py`:
"websockets are not allowed: the gate cannot judge their frames"), and `bh-browse` refuses them locally.
Copilot chat UIs probably use websockets [inferred, to measure: `WebSocketCopilotTarget` defaults to
`wss://substrate.svc.cloud.microsoft/m365Copilot/Chathub`]. So:
- Measure first: one `bh-browse` of the chat page as B; its summary prints "websockets: N refused".
- Websocket-only chat: **unreachable today**. `bh-note blocked other "websocket-only chat: <url>"`.
  A bounded websocket mode in the gate (frames judged or capped) is to be designed; decision for Mio.
- HTTP alternative when it exists: an HTTP API of the same assistant, a channel that answers over plain
  HTTP, or the injection side only (A writes mail/files over HTTP) with B's trigger through an HTTP surface.
- `bh-browse` starts one Chromium per command: no persistent page to hand to `PlaywrightTarget` /
  `PlaywrightCopilotTarget`. Not usable as is. Same for doc 15's "start with Copilot" recommendation.

**v1 without PyRIT: native converters.** In the default mode (no LLM), PyRIT would only bring
deterministic converters, at the cost of a large third-party dependency in the agent image with an API
that already broke once. v1 = four converters in `bh-agent` (stdlib; text-in-image may need a tool already
in the Kali image, to check): **Base64**, **Unicode tags** (ASCII smuggling), **text in image**, **PDF**.
The hunting agent writes the payload text, translated or restyled versions included, and picks the
stack. PyRIT comes back only if multi-turn attacks prove necessary (decision for Mio).

**Shape.** A builtin taking a small recipe (target spec, payload file, converter stack, oracle), one Bash
command, so hooks, lock and program rules apply. The recipe sets `X-BH-Identity` (`--as A` for the
planting write, `--as B` for the trigger); cookies are injected by the gate, never in the recipe. Each
variant records the HAR flow id of its request(s) next to its oracle result.

**Rate.** Gate token bucket is the hard limit; also a cap per call, per surface and **per day**. A 429 or
WAF challenge ends the call. Classing it as a test tool under `scanners_allowed: false` is a reading of
MSRC rules, not a technical fact (no threshold is published): **Mio's decision, written in the scope**.

**Output.** <= 25 lines: recipe, variants sent, per-variant oracle result (hit/miss/refused/error), first
hit with its HAR flow id. Raw: `raw/inject/<id>/` with each converted payload, responses, `recipe.json`.

**Judge.** The target is a non-deterministic LLM; stage A replays reads twice and writes once
(`docs/architecture.md` §7). So: fixed threshold k/N (e.g. 2/3 on replay), a replay budget per finding,
and the planting write (A's mail or file) is replayed once by the judge as A, or the hunter's plant is
reused if replay would double production traffic (to decide). Payloads and target responses reach the
judge only as tagged, bounded data; **only the deterministic oracle decides**.

**Which LLM generates attacks and scores?**
- **v1: none.** The hunting agent writes payloads; oracles are deterministic. No extra relay requests.
- **`ClaudeChatTarget` through the relay: excluded.** The relay only injects Claude Code's OAuth token,
  checks betas, model and body, and counts against the run budget (`addon.py`, `policy.py`); a LiteLLM
  client is out of that contract.
- **Third-party attacker model**: never a key in the agent. Only via a second relay in the gate, own
  budget, if multi-turn proves necessary. Decision for Mio; out of v1.

**Acceptance for a first version.** Against a local mock assistant we run (`bh target local`; to build):
state which model plays the assistant and on which budget (a regex fake only tests plumbing). A recipe
with a canary goes through the gate **over HTTPS** (positive test through the gate's proxy and CA, the
known blind spot of the HTTP lab), at the configured rate; summary <= 25 lines; raw dir holds payloads and
responses; the judge reaches the k/N threshold on replay.

## 7. Verify before use

- PyRIT: https://github.com/microsoft/PyRIT, v0.10.0 release notes; every class against the installed version.
- The websocket measurement on the actual target UI, dated.
