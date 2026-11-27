---
name: msrc-onedrive
description: Use when the program is OneDrive personal (MSRC, Microsoft 365 bounty) with our two accounts, for its surfaces in order, sharing and invitation limits and the proof MSRC wants.
---
<!-- Converted from src/bh/cards/msrc-onedrive.md (ours): every line kept word for word, its labels became the rubrics below. Added: the False positives rubric. Nothing removed. W4-G completed it from docs/research/21-releve-hotes-outlook-onedrive.md and scopes/msrc/onedrive.yaml (hosts of the scope, surface 7, the hosts left out, the recipient guard, payload hosts, what was not surveyed); every earlier line kept. -->
# Program card: OneDrive personal (MSRC, Microsoft 365 bounty), our two personal accounts

## When
Always on this program. Accounts: user-a and user-b only, no subscription. What pays: one account reads or
changes the other's file, sharing link or permission. Roles: each identity plays either role, victim or attacker;
every intent names its own ("<surface>: victim user-a, attacker user-b").
Hosts (survey of 2026-11-26, the scope block holds them): `onedrive.live.com`, `api.onedrive.com`, `d.docs.live.net`,
`my.microsoftpersonalcontent.com` under `/personal/`, and `graph.microsoft.com` under the `copilotuploads` prefix only.

## Do
1. Map in at most 10 turns: `bh-crawl <url>` once per in-scope origin, no `bh-recon`. `bh-web state` says who the
   browser is; over HTTP you are `q -a user-a` or `q -a user-b`. A blank page: `bh-web goto https://onedrive.live.com/`
   once. The app's API calls: `bh-web net --last 200` (manual: card bh-web-manual, pinned below).
2. Marker: `bh-note canary`, written into a small text file of the victim (`bh-web upload <css> <file>` in its
   OneDrive, at most 256 KiB). Note the file's `id` and the drive `<CID>` from `bh-web net`.
3. Surfaces, top first. Before each: `bh-note intent "<surface>: <step>"`.
   | # | Surface | Proof |
   |---|---|---|
   | 1 | The attacker reads the victim's drive or file over HTTP: `/v2.1/drives/<CID>` and the file routes `bh-web net` showed | --proof |
   | 2 | Sharing link made by the victim (names nobody): the attacker reads it; then the victim revokes it and the attacker reads again | --proof, --observation |
   | 3 | Invitation of the other account only: what the invited account may do beyond what was granted | --proof |
   | 4 | The attacker writes (rename, move, delete) on the victim's file, then the victim re-reads it | --proof |
   | 5 | `d.docs.live.net/<CID>/<path>` and `uploadSession` URLs of the victim, asked by the attacker | --proof |
   | 6 | Classic web on onedrive.live.com (redirect, CORS, CSRF) | --proof |
   | 7 | The `copilotuploads` folder over Graph and its upload session: the victim's ids asked by the attacker | --proof |
4. Per route, at most 8 per segment: `qq <url with the victim's id>` (one line per identity and anonymous), then
   `q -a <attacker> -n 2000 <url>` when the attacker gets 200. The canary in the attacker's body: candidate.
5. A write as the attacker: one `q -a <attacker> -X <method> <url>` per route, on the test file of step 2 only.
6. A link or a permission the victim made in the UI: revoke it in the UI at the end of the surface; a revocation
   that still lets the attacker read is the finding (surface 2), re-read 3 times over 2 minutes.
7. A UI-only read: `bh-web switch <attacker>` (card bh-web-manual, at most 2 per segment), open the victim's link,
   `bh-web text --tail 1500`. The canary on screen = candidate: the gate journaled it under the attacker.
8. Surface 6: the site a redirect or a CORS test names is `<payload-host>` (`<payload-host>`: the payload hosts of your scope block; none listed: `bh-note blocked other "no payload host declared"`).
9. Surface 7: a `me` route always answers for the caller; the victim's ids come from `q -a <victim>` on the routes
   `bh-web net` showed (the `graph` skill: method). A file uploaded through Copilot lands in the account's
   `Microsoft Copilot Chat Files/` folder: an id to read there, never to guess.
Next: `bh-note frontier`, then the first surface of the table with no fact or finding on the board.

## Proof
HTTP replay with its twin. proof.json = setup `"as": "<victim>"` expecting the canary, attack
`"as": "<attacker>"` expecting `{"status": [200], "contains": ["<canary>"]}`, control `"as": null` expecting
`{"status": [401, 403, 404]}`. Then `bh-note finding "<title>" --severity high --class idor --url <url> --proof
proof.json --summary "<who read what, 3/3>" --not-proven "<what you did not test>"`. UI-only:
`bh-note finding "<title>" --severity high --class idor --url <url> --observation <canary> --victim <identity>
--attacker <the other> --summary "<...>"`. MSRC Important = `--severity high`, Critical = `critical`.
MSRC wants: exact URLs, both personal accounts (user-a, user-b), the file and link ids, k/N, UTC times; the
operator re-reads the program page before any report.

## Never
Invite or write to an address that is not the other account's. On an invite or grant path the gate refuses
any other recipient, and an invitation that names nobody by address (`recipient not ours`): do not retry it.
Never touch a file, a link or a mail that is not ours, nor guess or enumerate ids (stay far below the gate's limit
of distinct ids per route). Third-party data: stop, `bh-note blocked third-party-data "<route, no content>"`.
Not in this scope, though the survey saw them (Copilot Notebooks, Loop): `home.microsoftpersonalcontent.com`, the
`collabhubrtc` websocket and the people picker `/v1.0/me/people`; never request them, `bh-note blocked other "<what,
which host>"`. No sign-in host is in this scope yet: a sign-in page in your way is `bh-note blocked auth "<where>"`.
The gate refuses sign-out, password, account and payment paths to every client: never look for another one.

## False positives
- A 404 on the other account's drive is isolation; an empty 200 or a sign-in page inside a 200 is not access.
- A link the victim made on purpose, read by the attacker before revocation: the design.

## Watch
Another account's drive answers 404 (seen live): a 404 is isolation, not an error to work around. A new
account has no drive until it opened onedrive.live.com once. An empty 200 or a sign-in page inside a 200 is not
access. Only the routes `bh-web net` showed; a host outside your scope block: `bh-note blocked other "<host>"`.
Not surveyed yet (2026-11-26): sharing (invitation, link), the recycle bin, versions. Surface 3 starts by noting what
`bh-web net` shows when the victim shares; any invite or grant path is held by the gate to our two addresses.
The rule pages are read by the host (`bh rules`), never by you; the operator re-reads the program page.
