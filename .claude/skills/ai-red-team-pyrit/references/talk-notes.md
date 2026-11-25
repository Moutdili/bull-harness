# Talk notes: "Zero Day Quest - Learn to Red Team AI Systems Using PyRIT"

- Channel: Microsoft Security Response Center (MSRC). Recorded 2 Dec 2024. 49 min 36 s.
- URL: https://www.youtube.com/watch?v=jq9DcEL3cHE
- Transcript: automatic (Gemini 2.5 Flash, 2026-11-25), no timestamps.
- **Positions are estimates**: character offset in the transcript body x 49:36. Expect +/- 2 min. The
  host intro takes the first ~2 min, so the real time is likely a bit later than shown at the start.
- Quotes are copied verbatim from the transcript, disfluencies included ("uh", repeated words).
- Tags: **[A]** = stated by a speaker. **[D]** = my deduction or an external check, not said in the talk.

## Speakers and transcription errors

| Transcript | Probably | Basis |
|---|---|---|
| "Pirate" | PyRIT | [D] title of the talk |
| "Rich Landine", "Richard Lundine", "Arlin D", "Arland Dean" | Richard Lundeen, PyRIT engineering lead | [D] GitHub user `rlundeen2` authors PyRIT PRs |
| "Martin Poliet" | AI Red Team member, MSRC MVR 2023; surname not checked | [D] |
| "MVR", "NVR" | Most Valuable Researcher | [D] |
| "Yohan", "Johan" | likely Johann Rehberger (Bing Chat injection, ASCII smuggling) | [D] name not confirmed by the talk |
| "Garrick and Dreadnode" | garak (NVIDIA) and Dreadnode | [D] |
| "Gandalf from uh LaCara" | Gandalf by Lakera | [D] |
| "the prompting guide, uh the dot AI" | promptingguide.ai | [D] |
| "David Mayor" | the "David Mayer" name blocked by ChatGPT (late 2024) | [D] |
| "Integrity" (payments) | Intigriti | [D] speaker himself was unsure ("they might have changed it") |
| "aka.ms/secure-at" | MSRC Researcher Portal link; exact short link unclear | [D] do not use as is |
| "Zero Day class" | Zero Day Quest | [D] |
| "GPT 40" | GPT-4o | [D] |
| "translation wrap battle demo" | "rap battle" | [D] |

## Part 1: AI bounty program and AI bug bar (Martin, ~02:00-12:00)

- ~05:35 [A] Important/Critical needs a crossed user boundary: "you need to be able to cross that user boundary"
- ~05:39 [A] "it's not enough to just go on Microsoft Co-pilot and try and do your prompt injection in your own context."
- [A] New bug-bar categories: inference manipulation (prompt injection, input perturbation), model
  manipulation (training data, model weights, data/RAG poisoning), inferential information disclosure.
  Each must affect other users to reach Important/Critical. Model theft severity depends on whether the
  extracted data is confidential training data.
- ~08:30 [A] System prompt leak: "If you're able to leak such instructions, that's not in scope." Unless
  user-specific and confidential.
- [A] Input extraction (recreating other users' inputs, e.g. a packet-length side channel) is in scope.
- ~09:32 [A] "we do have rules of engagement and this is especially true with automated tooling such as Pirate."
- ~09:47 [A] Two accounts of your own: "you want to make sure that you create two users uh that you holy control" ("holy" = wholly).
- [A] Server-side execution: contact bounty@microsoft.com before going further; stay at PoC.
- ~10:21 [A] "Don't do any kind of denial of service testing."
- ~10:31 [A] "If you're able to bypass the rate limiting, by all means uh let us know" (but do not use it for DoS).
- ~10:48 [A] "make sure that you uh that you're not abusing it and that you you do abide by the rate limiting that is in place."
- [A] No social engineering of Microsoft employees, partners or vendors; respect service agreements.
- ~11:42 [A] "a high quality report will include screenshots, steps to reproduce and a proof of concept."

## Part 2: PyRIT (Rich, ~12:00-28:00)

- [A] Bounty-relevant AI security = an attack affecting another user: exfiltration, privilege
  escalation, manipulating another user's output; often an app-sec slant.
- ~13:33 [A] Example (Bing Copilot reading a malicious page, exfil via image request): "It does a, it does a image request to his malicious server." Not found with PyRIT.
- ~14:11 [A] Mitigation may be architectural: "the right mitigation might have been on the application architecture layer, like maybe something that, uh, that that stops external requests"
- ~14:35 [A] "Pirate won't help you come up with the attack or the scenario you're trying to do."
- ~15:27 [A] "But you don't get bounties for convincing Chat GPT to tell you how to make meth."
- ~16:03 [A] "AI Red Team has found a lot of bugs that are caused because product teams improperly rely on things like metaprompt engineering or fine tuning."
- ~16:22 [A] "Each are LEGO block interfaces that can be swapped out."
- ~16:25 [A] "Orchestrators are the top-level components. They're where all the attack strategy and logic is consolidated."
- ~16:33 [A] "they're the one component that that's not an interface" (PAIR, TAP, Crescendo, Skeleton Key, Flip attack live there).
- [A] Datasets: Molotov cocktail is the stand-in objective; replace it with your scenario.
- ~18:07 [A] "Converters are a piece that prompts that convert the prompt from one thing to another thing." Examples: Base64, Caesar, Italian translation, image, audio.
- ~18:25 [A] "when an orchestrator sends a prompt, they almost always go through our converter stack."
- ~18:40 [A] Targets need not be models: "They can also be something like an Azure Blob storage, where you upload documents that are later consumed by an AI application." Also SharePoint.
- ~19:36 [A] "In this talk, I don't talk about scorers very much"
- ~19:53 [A] Scorer often unneeded: "you can kind of just see if it worked based on exfiltrating data"
- ~20:33 [A] Docs example: "it's OpenAI chat target, so we're talking to GPT-4o in this case."
- ~20:37 [A] "we have a Crescendo orchestrator." ~20:51 "We give it the adversarial chat, our scoring target." Plus emoji converters.
- [A] Multimodal (images, audio); targets can be blobs or SharePoint; scorers can base success on anything.
- **Memory: not mentioned anywhere in the talk.** [A, by absence]
- ~22:54 Email-Copilot scenario [A]: "to be the most useful, you'll probably need to program and build certain pieces that that don't exist."
- ~23:18 [A] "here I have an email target, which which doesn't exist, but all this would do is send the email." Also a custom MSG-template converter (not built).
- ~23:44 [A] "we have our prompt sending orchestrator, so this is something that just sends the prompts."
- ~24:09 [A] "Pirate's got a couple hundred simple jailbreaks and maybe one of these works." (DAN-style templates.)
- ~25:47 [A] Payload in an image attachment: "we're using the add image text converter." Then PDF attachment.
- ~26:20 [A] "You can just add an ASCII smuggler converter"; then a translation converter (Spanish).
- ~26:50 [A] "you can try rap battle language." Speaker claims no one trains against it (opinion, 2024).
- ~27:23 [A] "Converters are all stack, stackable"
- ~27:30 [A] "Pirate is really meant as a exploratory tool."
- [A] Other tools named: garak, Dreadnode (see errors table). New Discord server.
- [D] The email-target scenario is what PyRIT now calls XPIA (cross-domain prompt injection); the talk
  does not say "XPIA".

## Part 3: Q&A (~28:00-49:36)

- ~29:31 [A] Martin's method: "I always look at the integration."
- ~29:53 [A] "Do we have, for example, human in the loop? Do we have something that confirm a user action before doing that?"
- ~30:14 [A] "you can sort of see the AI as a black box"
- ~32:42 [A] "you can kind of use Pirate to build in some of that AI security knowledge"
- ~33:25 [A] Attacker LLM needed: "you need to have a generative AI endpoint that you're using for your infrastructure"
- ~33:41 [A] "the translation wrap battle demo uses an LLM on the back end"
- ~35:42 [A] Validate manually, keep notes: "by taking notes, you're able to go back on them"
- ~36:56 [A] Partial exploit: "Send send the case anyway", then update the case quickly with more impact.
- [A] Contact bounty@microsoft.com for questions or severity disagreement.
- ~40:02 [A] Attacker model: "Just GPT 40 out of the box would probably be the best" (for bounty-style injection; harm testing may want a less aligned model).
- [A] Most new PyRIT strategies come from external contributors.
- ~42:28 [A] "Most of these systems will actually be vulnerable to prompt injections."
- ~42:35 [A] Bypass = filter-evasion creativity: "it's always can you sort of be creative enough"
- ~43:32 [A] "today there's no like one good mitigation for prompt injection anywhere."
- [A] Trusted input / untrusted output that someone uses = place to dig.
- [A] Gandalf (Lakera) to practice; PyRIT can solve its levels.
- [A] Process (speaker's own 2023 experience): ack in a few days, answer ~2 weeks, payment email,
  MSRC keeps you informed until fix; coordinate before going public.
- ~48:24 [A] Final tip: "seeing where you can enter prompts and seeing where it's where it's input and output"

## External checks (not in the talk) [D]

Done 2026-11-25 with `gh api` on the repos below.
- `Azure/PyRIT` is archived; active repo `microsoft/PyRIT`, latest release v1.2.1 (2026-11-18), main @ `066b4e7421`.
- v0.10.0 release notes (2025-12-15): orchestrators -> attacks (`PromptSendingOrchestrator` -> `PromptSendingAttack`,
  `CrescendoOrchestrator` -> `CrescendoAttack`, `XPIAOrchestrator` -> `XPIAWorkflow`, ...), DuckDB -> SQLite,
  `initialize_pyrit` -> `initialize_pyrit_async` in `pyrit.setup`.
  Command: `gh api repos/microsoft/PyRIT/releases/tags/v0.10.0 --jq .body`
- Class names: exports of `pyrit/converter/__init__.py`, `pyrit/prompt_target/__init__.py`,
  `pyrit/score/__init__.py`, `pyrit/executor/attack/__init__.py`, `pyrit/memory/__init__.py`
  (`gh api repos/microsoft/PyRIT/contents/<path> -H "Accept: application/vnd.github.raw"`).
- `ClaudeChatTarget` (LiteLLM-based, `endpoint` parameter, `ANTHROPIC_API_KEY` default);
  `WebSocketCopilotTarget` default `wss://substrate.svc.cloud.microsoft/m365Copilot/Chathub`;
  `PlaywrightCopilotTarget` (consumer and M365); `PromptTarget(max_requests_per_minute=...)`.
- Blog `doc/blog/2026_09_03_adversarial_model_selection.md`: attacker model choice moves attack success
  rate by tens of points; less-aligned models tend to do better, technique-dependent.
- Not verified: which class did the "rap battle" rewrite in 2024; whether `FlipAttack` still exists.
