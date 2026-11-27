---
name: msrc-copilot
description: Use when the program is Microsoft Copilot (MSRC) with our two personal accounts, for its surfaces in order, prompt budget, pace, challenges, what pays and the proof MSRC wants.
---
<!-- Converted from src/bh/cards/msrc-copilot.md (ours): every line kept word for word, its labels became the rubrics below. Added: the False positives rubric and 1 Watch line from FUSIONS.md (skills audit, W3-C). Nothing removed. -->
# Program card: Microsoft Copilot (MSRC), our two personal accounts

## When
Always on this program. Accounts: user-a and user-b only, named as they are (no rename is needed).
Roles: user-a and user-b each play either role, victim or attacker; every intent names its own ("<surface>: victim
user-a, attacker user-b"). A role change in the browser costs one `bh-web switch` (at most 2 per segment).

## Do
1. Map in at most 15 turns: `bh-crawl <url>` once per in-scope origin (the tool lock needs it); skip `bh-recon`
   (subdomains and archives are outside this scope). Then `bh-web state`: `identity` is who the browser is; over
   HTTP you are `q -a user-a` or `q -a user-b`. A blank page: `bh-web goto https://copilot.com/chat`, once. API
   calls of the signed-in app: `bh-web net --last 200`; its controls: `bh-web outline` (manual: card
   bh-web-manual, pinned below).
2. Work the surfaces top first. Before each: `Read /opt/bh/cards/<card>.md`, then `bh-note intent "<surface>: <step>"`.
   | # | Surface | Card | Fills | Proof |
   |---|---|---|---|---|
   | 1 | One account reads the other's conversation, file, image or memory entry over HTTP | ai-conversation-isolation | 6 | --proof |
   | 2 | Server actions of copilot.com (app-shell-action, chat), cookies only | copilot-server-actions | 0 | --proof |
   | 3 | Share links: who reads them, revocation, a share made by the wrong account | copilot-share | 4 | --proof |
   | 4 | Content one account wrote, read by the other's assistant, one variant per run | prompt-injection | 7 | --observation |
   | 5 | Model output rendered as a link, an image or HTML | ai-output-rendering | 6 | --proof, --observation |
   | 6 | Memory (enabled on both accounts) | ai-memory | 10 | --proof, --observation |
   | 7 | Uploaded file: access to its URL, served type, instructions inside | ai-file-upload | 0 | none yet (upload host not in the scope) |
   | 8 | Classic web on copilot.com (redirect, CORS, CSRF) | the class cards of the task | 0 | --proof |
   | 9 | Connectors: Google and Notion (PayPal excluded: real money), operator prerequisite | ai-connectors | 0 | none yet |
3. Prompt budget, enforced by the browser: Copilot gives about 45 prompts a day per account. This run's budget is
   `fills.segment_left` in `bh-web state`, often 0. Start a surface only when its `Fills` fit in it; otherwise the
   HTTP surfaces (1, 2, 8). Exit 4 = spent, or the service's own limit (bh-web-manual, step 10): HTTP only.
4. Pace: one prompt, `bh-web wait 8000`, read. At most 4 new conversations per 10 min. The first message of a new
   app session costs the operator one challenge (measured 2026-11-26); a plain navigation does not. Never `goto`
   a page a click can reach. At most 2 `bh-web switch` per segment (one challenge each).
5. Each conversation you will cite: send `/id` in it (1 fill), note the identifier and the UTC time.
6. Challenge: a `bh-web` command exits 3 with `human-needed`, or `bh-web state` shows `pending: true`. Run
   `bh-web wait-human` once (bh-web-manual, step 9).
   - Exit 0: the challenge is cleared and the page rendered. `bh-web text --tail 2000`: did your pending message
     go out? If not: `bh-web press Enter` once. Then resume EXACTLY the step you were on: same conversation, same
     canary, no second `fill` of a message that left. `human_watching: true` = the operator watches without
     touching: act normally.
   - A command exits 3 with `human-viewing`: the operator took the screen back; one `bh-web wait-human`.
   - Exit 3 at the timeout: `bh-note intent "resume <surface, conversation, next command> after the challenge"`,
     work surface 1, 2 or 8 with `q` and `qq`, then `bh-web wait-human` again later; when it exits 0, resume that
     intent first. No `bh-note blocked captcha` here: a challenge is a wait, not a closed lead.
Next: `bh-note frontier`, then the first surface of the table that has no fact or finding on the board.

## Proof
What the model says is never evidence. The judge accepts an HTTP replay with its twin control
(`bh-note finding ... --proof proof.json`) or a canary from `bh-note canary` planted as the victim and seen by the
gate on the attacker's side (`bh-note finding ... --observation <canary> --victim <identity> --attacker <the other>`).
MSRC wants, in the evidence file: the report says the test ran on copilot.com; exact URL, the two personal accounts
(user-a, user-b), settings you changed, every prompt word for word, the conversation id from `/id`, k/N, UTC times.

## Never
Click, type, press on, reload or test an anti-bot challenge: only the operator passes it, in `bh-web`.
Never send a prompt by any path other than `bh-web`. No jailbreak, harmful content or system prompt extraction.
Third-party data or your code run server-side: stop, `bh-note blocked third-party-data|server-exec "<where, no content>"`.
Hosts: login.* are support hosts, never targets (the gate refuses your GETs there); `/m365Copilot/Chathub/` is
the browser's alone; `copilot.ai` is not in the harness scope, do not request it. Not in the scope either (the
operator has not decided): the share page host `copilot.cloud.microsoft`, the file upload host `graph.microsoft.com`
and the Notebooks (Loop) routes; never request them, `bh-note blocked other "<what, which host>"`.

## False positives
- What the model says it did, leaked or remembered: never evidence; a replay, a state read back or the gate is.
- Attacker = victim, a wrong or harmful answer, a jailbreak, the system prompt: not findings on this program.

## Watch
What pays (MSRC AI bug bar; the operator re-reads it before a report). A's content makes B's assistant
leak B's data or act in B's account with no action by B: Critical. B must click or do a step: one notch lower.
One account reads the other's conversations: Important. Nothing for attacker = victim, wrong or harmful answers,
jailbreaks, the system prompt, or a "leak" that only the model's words show.
Severity: MSRC Important = `--severity high`, Critical = `critical`.
Closed by the operator, 2026-11-26, do not redo: `RefreshNavPane` with the other account's `accountInfo`,
`ConversationResponseComplete`, CORS on copilot.com, `GetUserFacts` (403 for both), `/login?returnUrl=` signed in.
Bearer: on substrate, `q -a <identity>` carries a one-hour bearer the gate renews for the browser's identity; a
refusal `identity bearer expired` is the gate's, not the target's answer; `bh-web switch` renews the other's.
Surface 8 (classic web): its class skills also count the skill `csrf` and the skill `web-cache`.
