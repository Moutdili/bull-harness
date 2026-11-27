---
name: jwt
description: Use when the app hands your identity a JWT you can read (in a body, a URL, a share or invite link) and a route accepts it. Checks alg, signature, kid, expiry and audience; never cracks a secret.
---
<!--
Source: strix/skills/vulnerabilities/authentication_jwt.md, Strix (https://github.com/usestrix/strix), Copyright 2025
OmniSecure Inc., Apache License 2.0.
Also: inputs/skills-audit/FUSIONS.md, section "Classes T41", row "JWT" (points to the card `auth`, Do 2).
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form, on tokens issued to our own identities;
removed: the "Tooling" section (a tool we do not have, its attack-matrix mode and its secret brute force), kid path
traversal and injection into the key lookup, attacker-hosted JWKS or x5u chains, remote key fetch toward internal
hosts, refresh-token and mobile storage sections, chaining with token theft, the "Pro Tips" list.
-->

# JWT

## When
- A token of the form `eyJ...` is given to your identity where you can read it: an API body, a URL, a share or
  invitation link, a value the bundle stores. The session the gate injects is not one of them: the gate keeps it
  and you never hold its value.
- A route of the target accepts that token (header, query, body) and answers differently without it.

## Do
1. Decode it locally, nothing sent: `cut -d. -f1,2 | tr '.' '\n' | base64 -d 2>/dev/null`. Note `alg`, `kid`,
   `jku`, `iss`, `aud`, `exp`, `sub`, the role or scope claims. Record them as a fact (no signature, no value).
2. Baseline: the route with the untouched token as received, and without any token. Keep both answers.
3. One change at a time, each sent once, on a route that serves your own data:
   a. a claim changed (`sub` to your other identity's id, a role claim raised), signature left as is:
      accepted = the signature is not checked;
   b. `"alg":"none"` and an empty signature;
   c. if the issuer publishes its public key (`/.well-known/jwks.json`, read once): your token re-signed as
      HS256 with that key (algorithm confusion);
   d. `exp` in the past (a token you received earlier, or step a's form with an old `exp`);
   e. a token issued to your identity for another audience or another app of the same program, on this API.
4. Each accepted variant: who are you now? Read a route that names the identity. Accepted as yourself = weak
   check, a fact; accepted as your other identity, or with a role you do not have = the finding.
5. Header fields: `kid` and `jku` are read from the token. Check only whether the server uses them as sent (an
   error that quotes your `kid`); pointing them anywhere is out of bounds (Never).

## Proof
proof.json, with the forged token where the route takes it (a query or body value, or a header other than
`Authorization`):
- `attack`: the forged token, expecting the other identity's marker or the raised role's content;
- `control`: the same request with a token whose signature is broken (one character changed), expecting the
  refusal.
`Authorization` and `Cookie` cannot be set in a proof step (the identity is `as` only). A token that rides in
`Authorization` therefore gives a CANDIDATE fact with both answers attached (`-e`), and
`bh-note blocked other "jwt in Authorization: proof.json cannot carry the forged token"`.

## Never
- Guess, crack or brute-force a signing secret, with a wordlist or otherwise.
- Point `jku`, `x5u` or a `kid` at a host, a file or a key of yours, or at an internal address.
- Forge a token for an account that is not one of your identities (no admin id, no guessed id).
- Use the session token of the gate's identities: you never hold it, and a token copied from a page or a file is
  not ours to replay.

## False positives
- (Strix) A token refused because the audience or the issuer is enforced: the control working.
- (Strix) Keys pinned to a published set (JWKS) the server does not take from the token.
- (Strix) Short-lived tokens, rotated, revoked at logout: an old token refused is the design.
- (Strix) An ID token refused by an API that wants an access token.
- A token accepted after a change the server does not read (an unused claim): nothing gained.
- A JWT in a bundle that is a library's test fixture, or a public, unsigned config blob.

## Watch
- The class is `auth` when the forged token opens another identity's account (card `auth`).
- An encrypted token (five parts, JWE) cannot be edited: record it and move on.
- A token in a URL is also a leak through `Referer` and logs: a fact for the operator, not a JWT finding.
