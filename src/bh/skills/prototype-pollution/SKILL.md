---
name: prototype-pollution
description: Use when a JavaScript app merges your JSON or query keys into objects (deep merge, nested query parsing, state hydration). Tests __proto__ and constructor.prototype with a harmless marker key only.
---
<!--
Source: strix/skills/vulnerabilities/prototype_pollution.md, Strix (https://github.com/usestrix/strix), Copyright
2025 OmniSecure Inc., Apache License 2.0.
Also: inputs/skills-audit/FUSIONS.md, section "Classes T41", row "Pollution de prototype" (Hermes
prototype-pollution, mass-assignment-prototype-pollution, no licence stated): __proto__ and constructor.prototype
with a benign marker; execution payloads dropped.
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form; server-side pollution limited to the lab
or written permission (a polluted prototype is shared by every request the process serves); removed: server-side
code-execution gadget chains, command and require payloads, auth-flag pollution (`isAdmin` on the prototype),
denial-of-service effects, filter and WAF bypass lists, the "Tooling" section (fuzzers and scanners), the "Pro
Tips" list.
-->

# Prototype pollution

## When
- Client side: the app reads nested keys from the URL (`?a[b]=c`, a hash router) or merges a JSON it fetched or
  stored into its config or state. Look in the bundles for `merge`, `extend`, `defaultsDeep`, `$.extend(true`.
- Server side (Node.js): a route that deep-merges a JSON body into an existing object (settings, preferences,
  partial updates).

## Do
1. Marker: a key no code reads, `bhx` and 5 digits (`bhx12345`), with the value `bhx12345`. Never a key the app
   or a library uses (`isAdmin`, `role`, `shell`, `status`, `toString`, `json spaces`...).
2. Client side, in your browser only:
   - DOM before: `bh-browse '<page url>' --as <identity>` and keep the DOM it saves.
   - The same page with `?__proto__[bhx12345]=bhx12345`, then with `?constructor[prototype][bhx12345]=bhx12345`.
   - DOM after: the marker shows where no input of yours put it (an attribute, a config value rendered, a
     class) = the prototype was polluted. Compare with the DOM before.
   - A marker that reaches a script sink is an XSS: prove it with the card `xss` (`bh-browse --xss`), nothing
     else.
3. Server side, only on `platform: local` or with the program's written permission; anywhere else:
   `bh-note blocked other "server-side prototype pollution: shared process state, not tested"`. Lab: one body
   `{"__proto__":{"bhx12345":"bhx12345"}}` on your own object, then read a different object of your other
   identity: the marker there, not sent by it, is the pollution.
4. Record each merge point tested, also when clean:
   `bh-note fact "<route or page>: __proto__ keys dropped" -k dead-end --why technical`.

## Proof
- Client side: proof.json with `"browse": {}` steps. `attack`: the page with the polluting query, expecting the
  marker in the rendered DOM; `control`: the same page with the same query under a plain key
  (`?bhx[bhx12345]=bhx12345`), expecting it absent. If a script sink is reached: the card `xss` standard.
- Lab, server side: `attack` as the other identity reading its own object, expecting the marker; `control` the
  same read before the pollution (setup order) or on a fresh process, expecting it absent.

## Never
- A payload that runs code or a command (gadget chains on the server), or that changes how the server answers
  everyone (status codes, JSON spacing, headers).
- Server-side pollution on a real program: the prototype is shared by every request the process serves, so a
  third party's.
- A known property name as the marker.

## False positives
- (Strix) The parser drops `__proto__` before the merge: the marker never reaches the prototype.
- (Strix) Objects built with a null prototype throughout (`Object.create(null)`).
- (Strix) The key echoed in a JSON answer but never merged into an object.
- (Strix) Frozen prototypes in a hardened library: no change in behaviour.
- (Strix) A WAF that blocks the payload and every other encoding consistently.
- The marker visible because the page prints the query string: that is reflection, not pollution.

## Watch
- `constructor[prototype]` often passes where `__proto__` is filtered: one request each, no more shapes.
- Pollution with no gadget is a fact for the board; the finding is the effect (XSS, a changed decision).
- Second order: a stored JSON merged later (an import, saved preferences) pollutes when the page loads it.
