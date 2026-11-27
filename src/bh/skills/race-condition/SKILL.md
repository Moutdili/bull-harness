---
name: race-condition
description: Use when an action of your own account may happen only once (redeem a coupon, a transfer, a single vote, a limited purchase, a one-time token). Two simultaneous requests, never a burst.
---
<!--
Source: strix/skills/vulnerabilities/race_conditions.md, Strix (https://github.com/usestrix/strix), Copyright 2025
OmniSecure Inc., Apache License 2.0.
Also: inputs/skills-audit/FUSIONS.md, section "Classes T41", row "Courses" (Hermes race-condition-attacks and
race-condition-exploitation, no licence stated): the targets list; their bursts of 20 to 50 requests dropped.
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form, bound to our two identities and to two
requests; removed: bursts and ramping up parallelism, connection warming and last-byte synchronisation tooling,
spreading requests over IPs, sessions or accounts to dodge throttles, degrading the target to widen the window,
rate-limit and quota bypass, retry storms, cross-service sagas, the "Pro Tips" list.
-->

# Race condition (two requests)

## When
- A state change that the business allows once: redeem a coupon or gift card, a transfer of in-app credit or
  points, a single vote or like, an invitation tied to a unique address, a limited purchase, a one-time token consumed.
- The action is on your own account and is cheap to undo or harmless if done twice.
- Not when your scope block excludes race conditions: the program does not pay for the class.

## Do
1. The rule, written first: "coupon X once per account", "balance never below 0". One line in
   `bh-note think "<rule>" --why "race target"`.
2. Sequential baseline, on the other identity: do the action, then do it again. The second must be refused.
   Keep both answers: this is the twin control (the rule holds when the requests do not overlap).
3. The race, on the first identity: exactly two requests sent at the same time, same body, same session:
   `q -a <identity> -X POST -j '<body>' <url> & q -a <identity> -X POST -j '<body>' <url>; wait`
   Two requests, once. Not ten, not a loop, not a second round "to be sure".
4. Read the state, never the statuses: the account's balance, the coupon's uses, the vote count, the order
   total (`q -a <identity> <read url>`). Two 200s with one effect is no race.
5. Rule broken (two redemptions, a negative balance): go to Proof. Rule held: one fact and change target:
   `bh-note fact "<route>: two simultaneous requests, rule held" -k dead-end --why technical`.
6. Undo what can be undone (cancel the second order, remove the second vote).

## Proof
proof.json, both identities ran the same action on their own accounts:
- `attack`: as the identity that sent the pair, the read of the state, expecting the broken rule as a marker
  (`"uses":2`, the doubled credit, the second vote);
- `control`: the same read as the identity that sent the two requests one after the other, expecting the rule
  kept (`"uses":1`).
Attach the two raced answers and their times (`-e`). In `--not-proven`: "the race itself is not replayed: the
proof reads the state the pair left; one pair was sent".

## Never
- More than two simultaneous requests, or more than one pair per action. A burst is load on a real system.
- Race a payment, a refund or anything that moves real money, or another person's object.
- Spread requests over identities, sessions or addresses to get past a limit.
- Slow the target down to widen the window.

## False positives
- (Strix) An operation that is idempotent by design: an idempotency key, an ETag or version check, or a unique
  constraint refuses the second write.
- (Strix) A screen that shows the effect twice while the stored state has it once: a visual glitch, not a race.
- (Strix) A limit that refuses the excess with an atomic counter: the control working.
- Two success answers and one stored effect (the second request was deduplicated after answering).
- A rule the program states nowhere: "twice" is only a bug when the product says "once".

## Watch
- The same action through another channel (GraphQL mutation, the web form, the API) may lack the lock the first
  one has: one pair per channel, still on your own account.
- The gate paces requests to the program's rate: if the pair arrives one after the other (times far apart in the
  answers), the race was not run. Record that, do not try harder.
- A raced invitation names your other identity's address only (the gate refuses other recipients). Never sign
  up a new account to race a sign-up.
