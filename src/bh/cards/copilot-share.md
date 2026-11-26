## Share links: who can read a shared conversation or page, and for how long
When: the UI has a share control (conversation, page, group) or `bh-web net` shows a share route.
Never: guess, shorten or increment a link; open a link you did not create; leave a share alive after the test; a
challenge touched or a prompt sent outside `bh-web`. Someone else's content behind a link: stop,
`bh-note blocked third-party-data "<link host and path shape, no content>"`.
Do:
1. Owner = the identity `bh-web state` names; reader = the other identity, over HTTP.
2. Content (2 fills): a new conversation holding a canary (`bh-note canary`), then `/id`, as in step 2 of the
   card ai-conversation-isolation. Reuse that conversation if the board already has one.
3. Share it: find the control with `bh-web outline`, click it, then read the link: `bh-web text --tail 800`,
   or `bh-web attr '<css of the link field>' value` (or `href`), or the create request in `bh-web net --last 30`.
   No control found in 6 turns: `bh-note fact "share: no control found" -s "<outline lines seen>" -k dead-end`,
   next surface. Found: `bh-note fact "copilot share" -s "control=<css>; create=<METHOD url>; link=<host and
   path shape, id length>" -k recon`.
4. Baseline, without the reader: `q -a <owner> -n 300 <link>` and `q -n 300 <link>` (anonymous). A public link
   that everyone reads is the product's design, not a finding.
5. Revocation, the test that matters: unshare or delete the share in the UI, note the UTC time,
   `bh-web wait 30000`, then `q -a <reader> -n 2000 <link>` 3 times over 5 minutes. 200 with the canary =
   candidate, with k/3.
6. Deletion: delete the test conversation as the owner, then one `q -a <reader> -n 2000 <link>` on its old link.
7. A share made by the wrong account: replay the create request of step 3 as the reader on the owner's
   conversation id, once: `q -a <reader> -X <method> -j '<the same JSON body>' <create url>`. A link in the
   answer = candidate.
8. Shares limited to signed-in or named people: `qq <link>`. 200 with the canary for the account that was not
   invited = candidate.
9. What the reader's browser renders: `bh-browse '<link>' --as <reader>` once (status, title, requests). Markers
   and script: card ai-output-rendering.
10. Clean up: unshare, delete the test conversation; `q -n 200 <link>` must no longer return the canary.
Watch: before step 5 the reader must never have fetched the link (`qq` would do it): the gate would then show the
canary reaching the reader while the share was valid. A cached answer: `bh-web wait 30000` and read again before
concluding. A link only the owner's session can read is a private URL, not a share.
Proof: steps 7 and 8 replay over HTTP. proof.json: attack `"as": "<reader>"` expecting the canary (or the new
link), twin control `"as": null` on the same method and URL expecting `{"status": [401, 403]}`. Then:
`bh-note finding "<title>" --severity <s> --class broken-access-control --url <u> --proof proof.json --summary
"<...>" --not-proven "<...>"`.
Steps 5 and 6 have no twin (everyone gets the same answer): the canary must reach the reader only after the
revoke. `bh-note finding "<title>" --severity <s> --class broken-access-control --url <link> --observation
<canary> --victim <owner> --attacker <reader> --summary "<revoked at HH:MM:SS UTC, read at ..., k/3>" -e <file>`.
MSRC wants: the link, both personal accounts (user-a, user-b), the conversation id from `/id`, the prompt of
step 2 word for word, k/N, UTC times of share, revoke and each read. The model's words are never evidence.
Next: `bh-note intent "share: step <n>"` for the first step without a fact on the board, then run it.
