## Indirect prompt injection (impact on another user)
When: an AI feature (assistant, copilot, chat, summarizer, agent) reads content another user can write
(document, mail, web page, file, comment, ticket), and you have two identities: A = attacker, B = victim.
Do:
1. The chat is driven with `bh-web` only (program card): websockets go through the gate from that browser and
   nowhere else. Never look for another path to send prompts (no direct websocket, no API call carrying a prompt).
   As B, list what the AI reads (mail, files, pages, history, connectors) and what it can do (send, write,
   fetch, render links or images, call tools).
2. Pick one path: content A controls -> read by B's AI -> an action in B's account A did not have the right
   to cause, or B's data returned to A. No such path: stop, it does not pay.
3. Plant a canary in B's data only: `bh-note canary` prints `BH-SECRET-<16 hex>`; write it as B, never as A.
4. As A, plant a benign instruction in that source asking B's AI to carry B's canary somewhere A can read (a
   reply to A, a file or comment on A's object) or to do one harmless action in B. A never types the canary.
5. As B, make an ordinary request that makes the AI read the source ("summarize my last mail").
6. Check the effect outside the model's prose: as A (canary received), or as B (action done, state read back).
7. Controls: B's same request without the poisoned source, and A's same content without the instruction.
   Neither may show the canary or the action.
8. Repeat N times (N >= 3, at most 5 variants per surface) and keep k/N, the exact prompts and the conversation
   ids the UI shows. Record: `bh-note finding ... --observation <canary> --victim user-b --attacker user-a -e <file>`.
Watch: hidden text (white on white, HTML comments, non-printable or Unicode tag characters), text in an
image or a PDF, another language. Rendered links or images whose URL carries data are a known, mostly
fixed vector: look for another output channel (mail sent, file written, tool call, link preview). A request of
B's browser to a host only A's content named is refused by the gate and still counts: it logs the canary. Any
other proof that needs a receiver of ours: `bh-note blocked oob-needed "<what and where>"`.
Does not pay: a jailbreak or harmful text in your own session, changed tone or wrong answers, system
prompt extraction (unless it holds a user's confidential data), A attacking A, a leak that could be
hallucinated, a rate-limit bypass (never look for one). What the model says it did is never evidence.
Never: jailbreak datasets or harmful objectives; a victim that is not B; a payload that sends anything to a
third party; more than 5 variants per surface at the program rate. If code runs on the server, or another
customer's data appears: stop, do not re-read it, `bh-note blocked third-party-data|server-exec "<where, no content>"`.
