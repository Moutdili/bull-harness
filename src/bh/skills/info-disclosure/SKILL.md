---
name: info-disclosure
description: Use when you meet backups, configs, debug or metrics routes, logs, `.git`, source maps, exports or verbose errors that may hold a secret or another user's data.
---
<!-- Source: card src/bh/cards/info-disclosure.md (ours), plus the lines FUSIONS.md (skills audit, W3-C) drew from the
Hermes skills security/search-cve, bug-bounty/sqlite-attacks, review-ombre and review-nemesis (no licence stated).
Modified: rewritten for this harness; nothing removed beyond what the card already forbade. -->
# Sensitive information disclosure

## When
- Backups, configs, debug/metrics/actuator, logs, `.git`, exports, verbose errors.
- Database side files (`.db-wal`, `.db-journal`), source maps (check they are JSON).

## Do
1. Open each candidate once and look for actual values: keys, tokens, passwords, connection strings, other users'
   data: `q -n 2000 <url>`. Check the content, not the status: a 200 HTML page of the same size on every path is
   the app shell, not the file.
2. Check whether a found secret is live with ONE harmless read-only call on the program's own service, if the rules
   allow it. A key for a third-party service is never sent there: record it as it is.
3. Record version banners and stack traces as facts (useful for other skills), not as findings:
   `bh-note fact "<host>: <component> <version>" -s "<where it shows>" -k recon`. Where versions leak: response
   headers, error pages, status or health routes, bundle comments. A version and a CVE make a lead only when the
   exact version is in the advisory's range.
4. Other users' data in an answer: one read, then the skill `idor` for the access question.

## Proof
An actual secret value or other users' personal data. When the exposure depends on who asks or on a parameter,
proof.json: attack (`"as": null` or the identity that should not see it) expecting a fragment that identifies the
value without copying it whole (the variable name and its first 4 characters); twin control = the same method and
path with the identity entitled to nothing more, or the parameter that selects it changed, expecting the fragment
`absent`. A static file has no twin that answers differently: `bh-note fact "CANDIDATE: <title>" -s "<path, the
kind of value, no value>" -e <file>`. `bh-note finding "<title>" --severity <s> --class info-disclosure --url
<url> --proof proof.json --summary "<what kind of secret, where>" --not-proven "<...>" --counter "<...>"
--severity-if "<...>" --severity-why "<...>"`.

## Never
- Use a leaked credential to go further than proving it is valid, download whole backups or databases.
- Copy a secret value into a fact, a summary or a report: name its kind and where it is.
- Send a secret to any host that is not the program's own service.

## False positives
- Field names, public specs, version banners and by-design data are not disclosure.
- Example or placeholder values (`changeme`, `xxxx`, a key that the service refuses).

## Watch
- Publishable keys are public by design: the finding is what the key gives access to.
- Source maps hold source, rarely secrets: read them for routes and parameters (skill `api-surface-mapping`).
- A `.git` directory answering is worth one `HEAD` file read; the rest is the operator's call.
- An error that echoes another user's data is access control, not disclosure (skill `idor`).
