## AI output rendering: what the UI does with links, images and HTML the model writes
When: an answer renders markdown, links, images, tables or HTML, in the chat or on a shared page.
Never: a payload that loads or sends anything to a third party; a script that does more than set the marker; a
payload loop or `--routes` (one page, one marker); a challenge touched or a prompt sent outside `bh-web`.
Server-side execution: stop, `bh-note blocked server-exec "<where, no content>"`.
Do:
1. Marker: `bhx` and 5 digits of your choice (not a canary). Test host: `<marker>.example.org`, outside the
   scope: the gate refuses it, nothing leaves, and `bh-web net` shows the attempt as a row with `failure`.
2. Contexts, 1 fill each, at most 6. Ask the assistant to answer with exactly: (a) a markdown link to
   `https://<marker>.example.org/l`; (b) a markdown image of `https://<marker>.example.org/i.png`; (c) the text
   `<b>marker</b><img src=x>` outside a code block; (d) a table cell holding (a); (e) a link whose text and
   target differ; (f) a `javascript:` link with the text "open". After each: `bh-web wait 8000`.
3. How it rendered: `bh-web outline --css '<css of the last answer>'` (a `link` or `img` line = rendered; the
   raw characters = escaped), then `bh-web attr '<css of that link or image>' href` (or `src`): kept,
   rewritten or proxied?
4. Fetch without a click: `bh-web net --last 30` (not `--denied`: a refused https host shows as `failure`). A
   row for `<marker>.example.org` that you did not click = the UI fetches model-written URLs by itself.
   `bh-note fact "render: <context> auto-fetches model URLs" -s "<the net row>" -k fact`. Alone it is not a
   finding (you asked for it yourself): it is the channel for the card prompt-injection, with the canary as
   the first label of the host.
5. Click-through, lower severity: click the rendered link once, then `bh-web tabs` and `bh-web net --last 10`.
6. Shared page: share the conversation (card copilot-share), then render it once as the other identity:
   `bh-browse '<share link>' --as <reader> --xss <marker>`. For script, context (c) becomes
   `<img src=x onerror="window.__bhxss='<marker>'">` (1 fill). Only the line `xss CONFIRMED (marker <marker>)`
   counts; `xss: marker <marker> not seen` = not confirmed.
7. One run per context is enough when the DOM shows the result. The model refuses to write the text: 2
   rephrasings at most, then `bh-note fact "render: <context> not produced" -k dead-end`.
Watch: image exfiltration through markdown was reported and fixed: expect a rewritten URL or a blocked load, and
look for the variant (another context, the shared page, a link preview). `bh-browse` runs in your own headless
browser, without the chat: it only proves what a page with a URL renders. The command must hold one literal
URL: no `$`, no loop, no second `bh-browse`.
Proof: script on a page with a URL = HTTP replay. proof.json: attack `{"name": "reader renders the page",
"role": "attack", "as": "<reader>", "method": "GET", "url": "<link>", "browse": {"xss": "<marker>"}, "expect":
{"contains": ["xss CONFIRMED (marker <marker>)"]}}`; control = the same step with another marker, role
`control`, expecting `{"absent": ["xss CONFIRMED"]}`. Say in `--not-proven` that this control only shows the
script is yours. `bh-note finding "<title>" --severity <s> --class xss --url <link> --proof proof.json
--summary "<...>" --not-proven "<...>"`.
Data leaving B's browser because of A's content: the observation proof of the card prompt-injection.
MSRC wants: exact URL, both accounts, every prompt word for word, the conversation id from `/id`, k/N, UTC
times. The model writing "I rendered it" is never evidence: the DOM, the refused request or the dialog is.
Next: `bh-note intent "render: context <letter>"` for the first context without a fact, then run step 2 on it.
