---
name: saml
description: Use when the target logs users in through SAML and its assertion consumer endpoint is in scope. Checks whether the service provider verifies what the assertion says, between your two identities.
---
<!--
Source: hermes/bug-bounty/saml-authentication-bypass/SKILL.md (no author or licence stated; it points to PortSwigger Web Security Academy, the SAMLRaider project and a CyberArk article on Golden SAML).
Modified: translated; target changed from "admin" to our second identity; Golden SAML (stolen identity-provider key) removed as post-exploitation; the source's "comment out SignedInfo" example removed as incorrect; harness limits, the twin control and the last two Watch lines are ours.
Role: hunter. The plan (T41) asks for this class; its proof standard is still to add in `classes.py`.
-->

# SAML: does the service provider check the assertion?

## When
- Login goes through an identity provider and comes back as a POST of `SAMLResponse` to the target.
- The receiving endpoint (assertion consumer service) is an in-scope target. The identity provider and any
  login host are never targets.

## Harness limits (read first)
- You never drive a login. You need one `SAMLResponse` issued for user-a: look for the POST to the consumer
  endpoint in what the browser tools recorded (`bh-web net --last 200`, or the summary of a `bh-browse`).
- None available: `bh-note blocked auth "saml: no SAMLResponse capturable in the sandbox"`, next surface.
- An assertion is short-lived: note its validity window before testing.

## Do
1. Decode: Base64, sometimes URL-encoded first. Find `Assertion`, `Signature`, `Subject/NameID`,
   `Conditions` (validity, audience).
2. Baseline: the untouched response, replayed once. Accepted or refused (replay protection)? Record it.
3. One change at a time, re-encoded, posted to the consumer endpoint with no session:
   a. `NameID` changed to user-b's identifier, signature left as is. Accepted = the signature is not checked
      against the content.
   b. The `Signature` element removed. Accepted = the signature is optional.
   c. Signature wrapping: keep the signed assertion, add a second, unsigned assertion that names user-b,
      in the positions the parser may read instead of the signed one. Accepted as user-b = wrapping.
4. For each accepted variant, find out who you are: the redirect target, a "whoami" page of the session the
   answer opened.
5. A secondary consumer endpoint (another path or host of the same application) may check less: test it the
   same way if it is in scope.

## Proof
- `attack`: the tampered response of step 3, expecting the answer of an accepted login for user-b;
- `control`: the same tampering with a broken digest, expecting the refusal.
- If the session cannot be shown through the gate (cookies are masked), record
  `bh-note fact "CANDIDATE: saml <variant> accepted" -s "<consumer url, both answers, UTC time>" -e <file>`
  rather than a finding.

## Never
- A `NameID` that is not user-b's: no administrator, no real user, no guessed address.
- Requests to the identity provider, or any attempt to obtain or use its signing key.
- More than a few posts: each one is a login attempt on a real system.

## False positives
- A refusal for every variant including the baseline: the response had expired.
- Accepted, but the session is still user-a: the provider read the signed assertion.
- A 200 that is the login page again.

## Watch
- Encoding mistakes look like a secure provider: confirm the baseline is accepted with your own
  encode/decode round trip before concluding anything.
- Standard checks the source does not list (ours): the same response accepted twice, and a response issued
  for another application accepted here (audience).
