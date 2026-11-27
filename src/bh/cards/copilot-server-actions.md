## Copilot server actions: app-shell-action and chat, played as the other account
When: the app calls `POST https://copilot.com/resources/app-shell-action` or `POST https://copilot.com/chat`
with a body `{"action": "<Name>", ...}`, the headers `x-route-id` and `Accept: application/json`, cookies only,
no bearer.
Never: an action on an object that is not ours (user-a's or user-b's); a burst of actions (one request, read the
answer, then the next); `ic3proxy` or substrate routes this way (they want the bearer: not this card); a
challenge touched or a prompt sent outside `bh-web`.
Do:
1. Action names: `bh-js` on the app's code, and `bh-web net --last 200` (rows for the two routes above;
   `bh-web net --body <i>` shows one answer). Keep the headers and the body as the app sent them.
2. Each name: `bh-note fact "server action <Name>" -s "<route; read or write; body fields; id field>" -k recon`.
3. Read action: as the owner of an object (a conversation holding a canary, a title only it has),
   `q -a <owner> -X POST -H 'x-route-id: <value>' -H 'Accept: application/json' -j '<body>' <route>`; then the
   same request `q -a <the other>` on that same object of the owner. The owner's data in the other's answer =
   candidate.
4. Write action: on our own object only. Play it as the other account on the owner's object, the owner re-reads
   the object, then undo it as the owner.
5. Every action played: `bh-note fact "server action <Name> played" -s "<as whom, on what, status>" -k recon`.
Watch: closed by the operator, 2026-11-26, do not redo: `RefreshNavPane` with the other account's `accountInfo`
(the server trusts the session); `ConversationResponseComplete` (an echo, no write); CORS (no
`Access-Control-Allow-Origin`); `GetUserFacts` (403 for both accounts); `/login?returnUrl=` signed in.
Open: a write action with impact that plays as a "simple" request from another origin (`Content-Type:
text/plain`, no `x-route-id`), which holds for `UpdateChatPinStatus`, without impact; and `returnUrl` from a
fresh session.
Proof: HTTP replay with its twin control. proof.json: setup `"as": "<owner>"` expecting the marker, attack
`"as": "<the other>"` expecting `{"status": [200], "contains": ["<marker>"]}`, control `"as": null` on the same
method and URL expecting `{"absent": ["<marker>"]}`; each step with the app's headers and body. Then:
`bh-note finding "<title>" --severity <s> --class broken-access-control --url <route> --proof proof.json
--summary "<action, who played it on whose object>" --not-proven "<...>"`.
Next: `bh-note intent "server actions: <Name>"` for the first action without a fact, then step 3 or 4 on it.
