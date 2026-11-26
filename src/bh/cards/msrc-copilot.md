## Program card: Microsoft Copilot (MSRC), our two personal accounts
When: always on this program. Accounts: user-a and user-b only, named as they are (no rename is needed).
Never: click, type, press on, reload or test an anti-bot challenge: only the operator passes it, in `bh-web`.
Never send a prompt by any path other than `bh-web`. No jailbreak, harmful content or system prompt extraction.
Third-party data or your code run server-side: stop, `bh-note blocked third-party-data|server-exec "<where, no content>"`.
Do:
1. Map in at most 15 turns: `bh-crawl <url>` once per in-scope origin (the tool lock needs it); skip `bh-recon`
   (subdomains and archives are outside this scope). Then `bh-web state`: `identity` is who the browser is; over
   HTTP you are `q -a user-a` or `q -a user-b`. A blank page: `bh-web goto https://copilot.com/chat`, once. API
   calls of the signed-in app: `bh-web net --last 200`; its controls: `bh-web outline` (manual: card
   bh-web-manual, pinned below).
2. Work the surfaces top first. Before each: `Read /opt/bh/cards/<card>.md`, then `bh-note intent "<surface>: <step>"`.
   | # | Surface | Card | Fills | Proof |
   |---|---|---|---|---|
   | 1 | One account reads the other's conversation, file, image or memory entry over HTTP | ai-conversation-isolation | 6 | --proof |
   | 2 | Share links: who reads them, revocation, a share made by the wrong account | copilot-share | 8 | --proof, --observation |
   | 3 | Content A wrote, read by B's assistant (shared page, file) | prompt-injection | 24 | --observation |
   | 4 | Model output rendered as a link, an image or HTML | ai-output-rendering | 10 | --proof, --observation |
   | 5 | Uploaded file: access to its URL, served type, instructions inside | ai-file-upload | 10 | --proof, --observation |
   | 6 | Memory, only when it is enabled on user-b | ai-memory | 10 | --proof, --observation |
   | 7 | Classic web on copilot.com (redirect, CORS, CSRF) | the class cards of the task | 0 | --proof |
   | 8 | Connectors (operator prerequisite) | ai-connectors | 0 | none yet |
3. Prompt budget, enforced by the browser: 80 `fill` per segment, 200 per identity and UTC day (`fills` in
   `bh-web state`). The table spends 68; the other 12 are for `/id` and retries. Exit 4 = spent: HTTP only.
4. Pace: one prompt, `bh-web wait 8000`, read. At most 4 new conversations per 10 min. Never `goto` when
   `bh-web state` shows the chat (each page load costs the operator one challenge). At most 2 `bh-web switch`
   per segment (one challenge each).
5. Each conversation you will cite: send `/id` in it (1 fill), note the identifier and the UTC time.
6. Challenge: a `bh-web` command exits 3 with `human-needed`, or `bh-web state` shows `pending: true`. Run
   `bh-web wait-human` once.
   - It prints "cleared": `bh-web state`. While `human_viewing` is true only state, text and frames answer: run
     `bh-web state` again each turn (never `wait-human` again). Then `bh-web text --tail 2000`: did your pending
     message go out? If not: `bh-web press Enter` once. Then resume EXACTLY the step you were on: same
     conversation, same canary, no second `fill` of a message that left.
   - It prints "still pending" (exit 3, after 300 s): `bh-note intent "resume <surface, conversation, next
     command> after the challenge"`, work surface 1 or 7 with `q` and `qq`, run `bh-web state` every 10 turns.
     As soon as `pending` is false, resume that intent first. No `bh-note blocked captcha` here: a challenge
     is a wait, not a closed lead.
Watch: what pays (MSRC AI bug bar; the operator re-reads it before a report). A's content makes B's assistant
leak B's data or act in B's account with no action by B: Critical. B must click or do a step: one notch lower.
One account reads the other's conversations: Important. Nothing for attacker = victim, wrong or harmful answers,
jailbreaks, the system prompt, or a "leak" that only the model's words show.
Proof: what the model says is never evidence. The judge accepts an HTTP replay with its twin control
(`bh-note finding ... --proof proof.json`) or a canary from `bh-note canary` planted as B and seen by the gate
on A's side (`bh-note finding ... --observation <canary> --victim user-b --attacker user-a`).
MSRC wants, in the evidence file: exact URL, the two personal accounts (user-a, user-b), settings you changed,
every prompt word for word, the conversation id from `/id`, k/N, UTC times.
Hosts: login.* are support hosts, never targets (the gate refuses your GETs there); `/m365Copilot/Chathub/` is
the browser's alone; `copilot.ai` is not in the harness scope, do not request it.
Next: `bh-note frontier`, then the first surface of the table that has no fact or finding on the board.
