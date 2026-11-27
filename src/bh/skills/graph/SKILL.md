---
name: graph
description: Use when your scope block lists a Graph-type API host (one API in front of many services) and the app calls it for both of our identities.
---
<!--
Source: ours (bull-harness, W4-G), written from the host survey docs/research/21-releve-hotes-outlook-onedrive.md and
the scope scopes/msrc/onedrive.yaml. Its access-control line follows the skills idor and broken-access-control (ours);
the "delegated versus application permission" idea comes from the identity part of strix/skills/cloud/azure.md, an
idea only, no text taken (no row in THIRD_PARTY_NOTICES.md).
Modified: nothing taken from elsewhere, nothing removed.
-->

# A Graph-type API: the other account's object, through one API

## When
Your scope block lists a host of a Graph-type API, one API in front of many services, with the exact prefixes the
survey saw (on OneDrive: `graph.microsoft.com`, under `/v1.0/me/drive/special/copilotuploads` only). The gate refuses
every other path of that host: the scope, not this skill, says what you may request.
The app calls it for both of our identities (seen in `bh-web net`). Not listed in your scope block: this skill does
not apply; `bh-note blocked other "<host>: not in the scope"` if the app needs it.

## Do
1. Map, 5 turns at most, as each identity: `bh-web net --last 100`; keep the calls to the Graph host and to the
   prefixes of your scope block. `bh-note fact "<host>: routes seen" -s "<method path family>; ..." -k recon`.
2. `me` in a route is always the caller: a `me` route asked as the attacker reaches the attacker's own objects,
   never the victim's. A cross-account test needs a route that names the victim's object by its id.
3. Ids come only from the victim's own answers: as the victim, `q -a <victim> -n 2000 <route>` on a route of step 1;
   note the ids of its objects (item id, drive id, the id inside an upload session). Never a guessed, incremented
   or listed id (stay far below the gate's limit of distinct ids per route).
4. Questions, in this order:
   a. Read: the attacker's token on the route that names the victim's object (`qq <url>`, then
      `q -a <attacker> -n 2000 <url>` when the attacker gets 200).
   b. Write: one `q -a <attacker> -X <method> <url>` on a test object of the victim created for it (a small file
      with a canary from `bh-note canary`, uploaded as the victim); the victim re-reads it.
   c. Upload session: a session URL the victim's upload created, asked by the attacker (the survey saw
      `createUploadSession` under the prefix above, then the bytes sent to the storage host of your scope).
   d. A field of the victim's object that names another account (a sharing entry, a person picker result): read it
      as the victim only; it is a lead for the program skill, never an id to try.
5. Twin control for each question: the same request as the victim on its own object (it answers as designed) and the
   same request anonymous (refused).
6. Undo as the victim every object the test created or changed, and re-read it.
Next: `bh-note intent "<host>: question <a-d>, victim <identity>, attacker <the other>"`, then step 4.

## Proof
proof.json: setup `"as": "<victim>"` reading its own object (the canary in it), attack `"as": "<attacker>"` on the
same URL expecting `{"status": [200], "contains": ["<canary>"]}`, twin control `"as": null` on the same URL
expecting `{"status": [401, 403, 404]}`. A write: the victim's re-read after it, in the same proof, expecting the
attacker's change. `bh-note finding "<title>" --severity <s> --class idor --url <url> --proof proof.json --summary
"<whose object, which route, read or write, k/N>" --not-proven "<...>" --counter "<...>" --severity-if "<...>"
--severity-why "<...>"`. The program's skill says the severity scale and what the report needs.

## Never
Request a path of the Graph host that your scope block does not list (the gate refuses it; do not look for another
one). Guess, increment, list or page through ids, users, drives or groups; a search or a list route used to find
someone else's object. A directory, a tenant, an application or a permission grant. Write to an object that is not
a test object of ours. Third-party data: stop, `bh-note blocked third-party-data "<route, no content>"`.

## False positives
- The attacker reading its own object through `me`: no victim.
- A 404 on the other account's object is isolation; an empty 200 or a sign-in page inside a 200 is not access.
- An object the victim shared on purpose with the attacker, read while the share stands: the design.
- A 403 from the API's edge (throttling, a missing consent of the app) is not the object's access check.

## Watch
One API, many services: the same object may be reachable through the service's own API (the program skill's
surfaces) and through the Graph host; test the route the scope lists, report the one that leaked.
A link to the next page in an answer is the server's: follow it only on the victim's own collection, as the
victim, never as the attacker.
A new account may have no object yet behind a `me` route (the survey: a 404 until the service was opened once).
