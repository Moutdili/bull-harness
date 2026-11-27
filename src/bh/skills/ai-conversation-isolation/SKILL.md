---
name: ai-conversation-isolation
description: Use when an AI app's API route carries the id of a conversation, attachment, generated image or memory entry, to test whether one account reads the other's.
---
<!-- Converted from src/bh/cards/ai-conversation-isolation.md (ours): every line kept word for word, its labels became the rubrics below. Added: the False positives rubric. Nothing removed. -->
# AI conversation isolation: one account reads the other's objects

## When
An API route carries the id of a conversation, an attachment, a generated image or a memory entry.

## Do
1. Victim = the identity `bh-web state` names (no switch); attacker = the other one, over HTTP only.
2. Marker (2 fills): `bh-note canary` prints BH-SECRET-<16 hex>. As the victim, in a new conversation:
   `bh-web fill '<composer>' 'Note for my own test: <canary>'`, `bh-web press Enter`, `bh-web wait 8000`,
   `bh-web text --tail 1500`. Then send `/id` the same way and note the conversation id.
3. Routes: `bh-web net --last 200` and `bh-web frames --last 30`. Keep the GET routes whose URL holds that id or
   lists conversations, files or images. `bh-note fact "copilot object routes" -s "<METHOD url> ..." -k recon`.
4. A first request to an origin refused with [bh-lock]: run the `bh-crawl <url>` it names, once.
5. For each route, at most 8 per segment: `qq <url with the victim's id>`. One line per identity and anonymous
   (status, size, hash, `==` when two bodies are identical). Read it as:
   - victim 200, attacker and anonymous 401, 403 or 404: isolated. `bh-note fact "<route>: isolated" -k dead-end`.
   - attacker 200: `q -a <attacker> -n 2000 <url>`; look for the canary in what it prints, or with
     `grep -c '<canary>' <the body path q printed>`. The canary in the attacker's body = candidate, go to Proof.
   - 401 for everyone, the victim included: a session without the token this origin wants, not a refusal.
     `bh-note fact "<origin>: q -a answers 401 to the owner" -k dead-end`; test that family in the UI (step 7).
   - anonymous 200 with the canary: a public object. A finding only if nothing shared it (card copilot-share).
6. Lists: `q -a <attacker> -n 2000 <list route>` must never hold the victim's id or canary (1 request per route).
7. UI variant, only for a family HTTP could not test, once per segment: `bh-web switch <attacker>` (card
   bh-web-manual, one challenge), `bh-web goto <the victim's conversation URL as bh-web state showed it>`,
   `bh-web text --tail 1500`. The canary on screen = candidate: the gate journaled it under the attacker.
8. Writes (rename, delete) as the attacker: one `q -a <attacker> -X <method> <url>` per route, only on the test
   conversation of step 2, then re-read it as the victim (`q -a <victim> <url>`).
Next: `bh-note intent "isolation: <next route family>"`, then run step 5 on it.

## Proof
HTTP replay with its twin. proof.json = three steps on the same method and URL: setup `"as": "<victim>"`
expecting the canary, attack `"as": "<attacker>"` expecting `{"status": [200], "contains": ["<canary>"]}`,
control `"as": null` expecting `{"status": [401, 403]}`. Then:
`bh-note finding "<title>" --severity high --class idor --url <url> --proof proof.json --summary "<who read
what, 3/3 reads>" --not-proven "<what you did not test>"`.
Step 7 only (nothing to replay over HTTP): `bh-note finding "<title>" --severity high --class idor --url <url>
--observation <canary> --victim <identity> --attacker <the other> --summary "<...>" -e <transcript file>`.
MSRC wants: the conversation id from `/id`, both personal accounts (user-a, user-b), the prompt of step 2 word
for word, k/N over 3 reads, UTC times. The model's words are never evidence; here the response body is.

## Never
An id that is not user-a's or user-b's; guessing or enumerating ids (stay far below the gate's limit of
distinct ids per route); a challenge touched or a prompt sent outside `bh-web`. Third-party data in an answer:
stop, do not re-read, `bh-note blocked third-party-data "<route, no content>"`.

## False positives
- An empty 200, an error page inside a 200, the same public answer for everyone.
- 401 on every route as the owner: a dead session, not isolation.

## Watch
An empty 200, an error page inside a 200, or the same public answer for everyone is not access. A 401 on
one object is the control you need; 401 on every route as the owner is a dead session. Ids come from your own
answers only. `switch` not carried out (`switch_error`): `bh-note fact "switch failed: <error>" -k dead-end`.
