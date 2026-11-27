---
name: subdomain-takeover
description: Use when an in-scope host answers with a hosting or storage provider's "no such site, bucket or app" page. Records the dangling host and its twin; the claim of the resource is left to the operator.
---
<!--
Source: strix/skills/vulnerabilities/subdomain_takeover.md, Strix (https://github.com/usestrix/strix), Copyright
2025 OmniSecure Inc., Apache License 2.0.
Also: inputs/skills-audit/FUSIONS.md, section "Classes T41", row "Prise de sous-domaine" (Hermes
subdomain-takeover, no licence stated): provider fingerprints; the sandbox has no DNS; the claim stays with the
operator.
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form; the hunter only observes; removed: the
subdomain enumeration pipeline and its tools, resolver sweeps, claiming the resource, alternate-domain and NS
delegation takeover, certificate issuance, cache poisoning after takeover, the web-search step (a tool we do not
have), the "Pro Tips" list.
-->

# Subdomain takeover (observe, never claim)

## When
- A host of your scope (named in the scope block, or met in the app's own links, CSP or bundles and let through by
  the gate) answers with a provider's "nothing here" page.
- Never on a host the gate refuses: out of scope is final, even for a takeover.

## Do
1. One request: `q -i -n 1500 https://<host>/`. Compare the body with the provider fingerprints:
   | Provider | Unclaimed page says |
   |---|---|
   | GitHub Pages | "There isn't a GitHub Pages site here." |
   | Fastly | "Fastly error: unknown domain" |
   | Heroku | "No such app", "There's nothing here, yet." |
   | S3 static site | "NoSuchBucket", "The specified bucket does not exist" |
   | Shopify | "Sorry, this shop is currently unavailable" |
   | CloudFront | 403 or 400 "The request could not be satisfied" (weak alone) |
   | Azure App Service | the default azurewebsites.net 404 (weak alone) |
2. Read the headers: a `server` header or an error header of the provider, where the program's own stack
   answers on its other hosts, supports the reading.
3. Twin: a sibling host of the same program on the same provider that works (its normal page). The difference
   between the two answers is the observation.
4. Where it is used: does the app load a script, a frame, an OAuth redirect or a cookie scope from that host (CSP,
   bundles via `bh-js`, the allowed callbacks)? That is what decides the impact.
5. Record and hand over:
   `bh-note blocked other "subdomain takeover: <host> answers <provider> unclaimed page; claim left to the operator"`.

## Proof
A CANDIDATE fact, not a finding: the finding exists only once the operator has claimed the resource and served a
page of ours there.
- attack: the anonymous `GET https://<host>/`, holding the provider's unclaimed message;
- twin control: the same request on the working sibling host, without that message.
`bh-note fact "CANDIDATE: subdomain takeover <host>" -s "<provider, fingerprint, where the app uses the host;
resource not claimed>" -e <both answers>`. No proof.json: its control must share the attack's host.

## Never
- Create, register or claim anything at a provider: a bucket, an app, a site, a domain, a certificate.
- Enumerate subdomains (wordlists, resolver sweeps, certificate log mining at scale): use the hosts the scope and
  the app already name.
- Resolve DNS yourself or reach the provider's API.

## False positives
- (Strix) An "unknown domain" page on a provider that requires a TXT or ownership check before binding: not
  claimable.
- (Strix) The provider's default page for a resource that exists and is owned by the program.
- (Strix) A soft 404 of the program's own infrastructure or a catch-all virtual host.
- A host that is simply down or times out: no fingerprint, no takeover.

## Watch
- Severity is the operator's call after the claim: an unclaimable provider page is low at most.
- A dangling host named in a CSP `script-src` or an OAuth callback list is the strongest lead: say it first in the
  note.
