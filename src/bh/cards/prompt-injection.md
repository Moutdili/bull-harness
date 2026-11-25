## Indirect prompt injection (impact on another user)
When: an AI feature (assistant, copilot, chat, summarizer, agent) reads content another user can write
(document, mail, web page, file, comment, ticket), and you have two identities: A = attacker, B = victim.
Do:
1. As B, list what the AI reads (mail, files, pages, history, connectors) and what it can do (send, write,
   fetch, render links or images, call tools). Measure the transport first: `bh-browse` on the chat page as B;
   "websockets: N refused" means the chat is unreachable through the gate: `bh-note blocked other
   "websocket-only chat: <url>"`. Use an HTTP path to the same assistant when one exists.
2. Pick one path: content A controls -> read by B's AI -> an action in B's account A did not have the right
   to cause, or B's data returned to A. No such path: stop, it does not pay.
3. As A, plant a benign instruction in that source asking B's AI to write `BH-CANARY-<id>` somewhere A can
   read (a reply to A, a file or comment on A's object) or to do one harmless action in B.
4. As B, make an ordinary request that makes the AI read the source ("summarize my last mail").
5. Check the effect outside the model's prose: as A (canary received), or as B (action done, state changed).
6. Controls: B's same request without the poisoned source, and A's same content without the instruction.
   Neither may show the canary or the action.
7. Repeat N times (N >= 3) and report k/N with the exact prompts and any conversation id the UI shows.
8. To show data impact, replace the canary with a test secret we planted in B's own data. Stop there.
Watch: hidden text (white on white, HTML comments, non-printable or Unicode tag characters), text in an
image or a PDF, another language. Rendered links or images whose URL carries data are a known, mostly
fixed vector: look for another output channel (mail sent, file written, tool call, link preview).
No receiver of ours exists: a proof that needs one is `bh-note blocked oob-needed "<what and where>"`.
Does not pay: a jailbreak or harmful text in your own session, changed tone or wrong answers, system
prompt extraction (unless it holds a user's confidential data), A attacking A, a leak that could be
hallucinated, a rate-limit bypass (never look for one).
Never: jailbreak datasets or harmful objectives; a victim that is not B; a payload that sends anything to a
third party; more than a few variants per surface at the program rate. If code runs on the server, or
another customer's data appears: stop, do not re-read it, `bh-note blocked other "<what, where, no content>"`.
