---
name: program-triage
description: Use when choosing the next bug bounty program for the harness, or deciding to park one. Scores a program on what the harness can reach and prove, and lists the signals to drop it early.
---
Source: hermes/pentest/bounty-target-selection/SKILL.md; merged from hermes/security/bug-bounty-methodology/references/rapid-multi-program-triage.md, hermes/pentest/pentest-workflow, hermes/arsenal-cavaliers, hermes/.archive/dev-human-patterns and hermes/web/blocked-page-recovery (Hermes Agent, MIT) (the others: no author or licence stated).
Modified: translated; bounty figures and tier lists that cannot be checked removed; harness readiness criteria are ours; third-party intelligence and any scan of a candidate removed.
Role: orchestrator, on the host. Onboarding stays a human decision: a program runs only once a human has set `automation_allowed` and `scanners_allowed` in its scope file.

# Program triage

## When
- Picking the program after the current one, or comparing three or four candidates.
- A program produced nothing for several segments: park or continue?

## Do
1. Read the program page yourself, today, and import it: `uv run bh scope import ywh <slug> --username <name>`.
   The import never widens a scope; free text is listed for you, not enforced.
2. Harness readiness, each a yes or a blocker:
   - automated testing allowed, and at which rate; scanners allowed or not;
   - two accounts obtainable without captcha, SMS, identity check or payment;
   - the valuable surface is reachable over HTTP(S) on web ports (no mobile app, no desktop client);
   - a required header or user-agent the gate can inject;
   - rules on AI-written reports (some programs suspend for unreviewed volume).
3. Value signals:
   | Signal | Reading |
   |---|---|
   | Few reports, recent program | less duplicate risk |
   | 4 to 10 assets | can be mapped in a few segments |
   | Recently shipped features, a public changelog | new code, fewer duplicates |
   | Source code or a public client available | patterns can be read, not guessed |
   | Disclosed reports to read | shows what was found and what the team accepts |
   | A stack with roles, tenants or sharing | cross-account impact is provable with two identities |
4. Where bugs concentrate (signals visible from outside): a feature announced for an event; a feature that
   spans two teams; an old core flow never refactored; a new content type; a framework default left as is.
5. Platform numbers, when the platform publishes them (the source cites a public endpoint of YesWeHack,
   `https://api.yeswehack.com/programs?search=<name>`, with report counts and reward bounds: to verify
   before relying on it). Queried from the host by a human or by you, never from the sandbox.
6. Order of work on a new program: stack first, then targeted reading (disclosed reports, changelog), then
   exploration. Never the reverse.

## Drop early
- A captcha or challenge on the only sign-up or on every form. Never worked around.
- The whole API behind a login we cannot obtain two accounts for.
- More than about two thousand reports already filed and no recent feature.
- Rules that forbid automation.
- An excluded list that covers what the harness proves best (access control between accounts).

## Never
- Send a request to a candidate before its scope file exists and a human set the two flags.
- Choose on a bounty table alone, or on a ranking from memory.
- Look for a way around a protection to "see if it is worth it".

## Watch
- Check each host separately before declaring a program blocked: protection is rarely uniform.
- An archived copy of a rules page is context, not the rules: cite it with its date, and read the live page.
- Track cost per verified finding per program; park when it only produces informatives.
