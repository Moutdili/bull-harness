---
name: business-logic
description: Use when the target has basket, checkout, payment, coupon, wallet, transfer, referral or subscription flows, or requests carry price, quantity or discount fields.
---
<!-- Source: card src/bh/cards/business-logic.md (ours), plus the lines FUSIONS.md (skills audit, W3-C) drew from the
Hermes skills bug-bounty/business-logic-attacks, business-logic-recon-methodology and bug-bounty/api-hacking-methodology
(no licence stated). Modified: roles left free; removed: probing account lockout by repeated logins. -->
# Business logic

## When
- Basket, checkout, payment, coupon, wallet, transfer, subscription routes; price or quantity fields.
- A multi-step flow (onboarding, trial, invitation, referral) whose steps are separate requests.

## Do
1. Walk every screen of the flow once as one of our identities and fill every field while the browser records
   (`bh-web net`, or `bh-browse --routes`): the list of calls is the map. Write the steps down
   (`bh-note fact "flow <name>" -s "<METHOD url> ..." -k recon`).
2. Change one thing at a time on our own objects: negative or huge quantity, price or currency in the request,
   coupon applied twice, a step skipped or replayed, an object of the other identity inserted into the flow; a
   negative amount on a coupon or tip; a list of coupons; `payment_method: null`; a trial or price field added to
   the request; cancel then reactivate without paying; one of our identities referring the other; a feature flag
   in a parameter or cookie; the last step called directly.
3. Check the total the server returns, not the parameter you sent. A 204 is not a success until a read shows the
   change. Keep the state before and after (totals, balances, order status) and both responses.
4. The whole flow without a session: if the first step answers anonymously, try each next step once.

## Proof
A rule of the business broken on our own account, shown with the state before and after and a control where the
rule holds. proof.json: attack = the altered request (`"as": "<identity>"`, the changed field in the body),
expecting the broken state in the answer (`contains` the wrong total, the second redemption accepted); twin control
= the same method and URL with the normal value, expecting that marker `absent`. Writes replay once; a second run of
the same write may answer 409, so use a fresh object per proof. Read the state back as a setup step.
`bh-note finding "<title>" --severity <s> --class business-logic --url <url> --proof proof.json --summary
"<rule, before, after>" --not-proven "<...>" --counter "<...>" --severity-if "<...>" --severity-why "<...>"`.

## Never
- Complete a real payment or order that costs the program money, touch real customers' objects.
- Replay an action many times (votes, redemptions): two requests show it.
- Keep what the flaw gave (credit, discount, plan): undo it or tell the operator in `--not-proven`.

## False positives
- A client-side total that the server recomputes on the next read.
- A discount the product grants by design (stacking allowed in the terms, a trial everyone gets).
- A 200 or 204 with no change in the state read back.

## Watch
- Two requests at the same moment rather than one after the other: skill `race-condition`.
- Fields the server should not take from the client (`role`, `plan`, `balance`): skill `mass-assignment`.
- A step that only the UI enforces: call the next API route directly, once.
