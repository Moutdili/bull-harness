---
name: power-platform
description: Use when your scope block lists a Power Platform host and two identities of ours sit in a tenant of ours. Dormant on personal accounts.
---
<!--
Source: ours (bull-harness, W4-G). No host survey under docs/research/ names a Power Platform host: this skill names
none and no route. It holds the method for the day the operator opens such a program with a tenant of ours.
Modified: nothing taken from elsewhere, nothing removed.
-->

# Power Platform (apps, flows, connectors): dormant

## When
Both, or this skill does not apply:
1. your scope block lists a Power Platform host (the operator adds it from a host survey, never you);
2. two identities of ours sit in one tenant of ours (an organisation the operator created, with its own licence).
Otherwise, and always on personal Microsoft accounts (no tenant, no subscription): not applicable on personal
accounts. Record it once, `bh-note fact "power-platform: not applicable on personal accounts" -k dead-end --why
environment`, and go back to the program skill.

## Do
1. Check the two conditions first (`bh-web state`, the identities of your task, your scope block); one missing: the
   fact of When, then stop here.
2. Inventory as the victim, 5 turns at most: the apps, flows and connections the victim owns, from `bh-web outline`
   and `bh-web net --last 100`; note each object's id from the victim's own answers. `bh-note fact "power-platform
   objects" -s "<kind: id, owner>; ..." -k recon`.
3. Questions, in this order, each between the two identities of our tenant:
   a. An app or a flow the victim did not share: the attacker reads or runs it (`qq <url>`, then
      `q -a <attacker> -n 2000 <url>`).
   b. A connection the victim created: does an app or a flow of the attacker run with it (the victim's credentials
      used for the attacker)? Read the effect in the victim's account, as in skill `agent-actions`.
   c. A share the victim made read-only: the attacker's write on it, one request, on a test object.
   d. A share revoked: the attacker's read, 3 times over 2 minutes.
4. Twin control for each question: the same request as the victim on its own object, and anonymous.
5. Undo as the victim every object created or changed, and revoke every share.
Next: `bh-note intent "power-platform: question <a-d>, victim <identity>, attacker <the other>"`, then step 3.

## Proof
proof.json: setup `"as": "<victim>"` on its own object (a marker from `bh-note canary` in it), attack `"as":
"<attacker>"` on the same URL expecting `{"status": [200], "contains": ["<marker>"]}`, twin control `"as": null`
expecting `{"status": [401, 403, 404]}`. `bh-note finding "<title>" --severity <s> --class idor --url <url> --proof
proof.json --summary "<whose object, which kind, read, run or write, k/N>" --not-proven "<...>" --counter "<...>"
--severity-if "<...>" --severity-why "<...>"`. An action run with the victim's connection: the proof of skill
`agent-actions` (the state change read back in the victim's account, with its twin control).

## Never
Run this skill on personal accounts, or in a tenant that is not ours. Create a tenant, buy or start a licence or a
trial, or invite anyone outside our identities. Request a host your scope block does not list. Run a flow that
sends, posts or pays outside our accounts: `bh-note blocked write-needed "<flow and why>"`. Guess or list ids,
environments or users. Third-party data: stop, `bh-note blocked third-party-data "<where, no content>"`.

## False positives
- An object the victim shared on purpose, used while the share stands: the design.
- An administrator of our tenant seeing a member's object: the role, not a flaw.
- A flow that runs as its owner by design, triggered by the owner itself.

## Watch
Dormant by default: no program of ours today has a tenant. The first run on a program that meets both conditions
starts with step 2 and nothing else.
A connection is a credential of its owner: the question that pays is b (someone else's flow running with it).
