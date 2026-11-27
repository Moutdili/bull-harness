---
name: copilot-share
description: Use when the Copilot UI has a share control or `bh-web net` shows a `sharelinks` route, to test what a share link opens, with which ids, and its redeem request.
---
<!-- Converted from src/bh/cards/copilot-share.md (ours): every line kept word for word, its labels became the rubrics below. Added: the False positives rubric and 1 Watch line from FUSIONS.md (skills audit, W3-C), drawn from the Hermes skill bug-bounty/web-cache-deception-attack (no licence stated). Nothing removed. -->
# Share links: what a share link opens, and with which ids

## When
The UI has a share control (conversation, page, group) or `bh-web net` shows a `sharelinks` route.

## Do
1. Owner = the identity `bh-web state` names; reader = the other identity, over HTTP.
2. Content (4 fills): two new conversations of the owner, each with its own canary (`bh-note canary`) and its
   `/id`, as in step 2 of the card ai-conversation-isolation. Reuse those the board already has.
3. Share the first one: find the control with `bh-web outline`, click it. The create request is
   `POST …/m365Copilot/conversations/<id>/sharelinks`, under the browser's bearer: its number `i` in
   `bh-web net --last 30`, the link in `bh-web net --body <i>`, or `bh-web text --clipboard` after the Copy
   control. The link carries a `shareId` and the `conversationId` (base64 JSON). No control found in 6 turns:
   `bh-note fact "share: no control found" -s "<outline lines seen>" -k dead-end`, next surface. Found:
   `bh-note fact "copilot share" -s "control=<css>; create=<METHOD url>; link=<host and path shape>" -k recon`.
4. Reading the link as the owner and anonymously: the link opens on `copilot.cloud.microsoft`, not in the scope.
   Never a request there: `bh-note blocked other "share read, copilot.cloud.microsoft"`.
5. Revocation, 6. deletion, 7. a share made by the wrong account, 8. shares limited to named people, 9. what the
   reader's browser renders: each needs that page or its requests. Never a request:
   `bh-note blocked other "share <step>, copilot.cloud.microsoft"`, once for all, then step 10.
10. Redeem with another conversation, under the `/m365Copilot/` prefix already in scope: the redeem request
   of the app (its path in the app's JS from `bh-crawl`, or in `bh-web net`; none found: `bh-note fact "share:
   no redeem route" -k dead-end`). As the reader, once: the valid `shareId` of step 3 with the `conversationId`
   of the owner's SECOND conversation, ours: `q -a <reader> -X POST -j '<the redeem body>' <redeem url>`. The
   second canary in the answer = candidate.
11. Clean up: unshare in the UI, delete both test conversations.
Next: `bh-note intent "share: step <n>"` for the first step without a fact on the board, then run it.

## Proof
Step 10 replays over HTTP. proof.json: attack `"as": "<reader>"`, the redeem request with the second
conversation's id, expecting `{"contains": ["<second canary>"]}`; twin control, same method and URL, `"as":
"<reader>"`, the same `shareId` with the shared conversation's own id, expecting `{"absent": ["<second
canary>"]}`. Then: `bh-note finding "<title>" --severity <s> --class broken-access-control --url <u> --proof
proof.json --summary "<...>" --not-proven "<...>"`.
MSRC wants: the link, both personal accounts (user-a, user-b), the conversation ids from `/id`, the prompts of
step 2 word for word, k/N, UTC times of share and each read. The model's words are never evidence.

## Never
Guess, shorten or increment a link or an id; open a link you did not create; leave a share alive after the
test; request the share page host `copilot.cloud.microsoft` (not in the scope, the operator has not decided); a
challenge touched or a prompt sent outside `bh-web`. Someone else's content behind a link: stop,
`bh-note blocked third-party-data "<link host and path shape, no content>"`.

## False positives
- A public copy that everyone with the link reads is the design.
- A redeem answer without the second canary: the share keeps its promise.

## Watch
The two promises of the app to test: "Anyone with a link can access a copy of this chat" and "Content
referenced in this chat can only be viewed with permission". A share of the first conversation that opens the
second breaks both. A public copy that everyone with the link reads is the design, not a finding.
A share page served through a cache, once its host is a target of your scope: read the cache headers before concluding on revocation (skill `web-cache` for the reading, not for its tests).
