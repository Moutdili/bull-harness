---
name: xxe
description: "Use when the server parses XML you control: XML or SOAP bodies, SVG, DOCX or XLSX uploads, or a JSON endpoint that also accepts `application/xml`. Entity expansion, proved with a marker."
---
<!--
Source: hermes/bug-bounty/xxe-injection/SKILL.md (no author or licence stated).
Modified: translated; ordered from least to most intrusive; `/etc/passwd` reads, out-of-band exfiltration to an attacker host and any expansion bomb removed; the internal-entity step and the twin control are ours.
Role: hunter. No class id exists yet (see out/README.md).
False positives merged from Strix strix/skills/vulnerabilities/xxe.md (Copyright 2025 OmniSecure Inc., Apache-2.0).
Modified from Strix (Apache-2.0) by bull-harness: its four "False Positives" lines reworded, network access
dropped, marked "(Strix)". modified (bull-harness W3-H): class standard now in classes_more.json.
-->

# XML external entities

## When
- `Content-Type: application/xml` or `text/xml`, SOAP, RSS or sitemap import, SAML.
- Uploads that are XML inside: SVG, DOCX, XLSX (skill and card `file-upload` for the upload itself).
- A JSON API: resend one request as XML once; an XML parser error is the lead.

## Do
1. Internal entity, no external access:
   `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY bhx "bhx12345">]><r>&bhx;</r>`
   in the field that is echoed back. The marker in the answer = the parser expands entities.
2. Error probe, still reading nothing: an external entity that points to a file that does not exist
   (`<!ENTITY x SYSTEM "file:///nonexistent-bhx12345">`). An error that names that path = external entities
   are resolved.
3. One read, once: the same with one well-known, world-readable, harmless file (`file:///etc/hostname`).
   Its content in the answer is the proof. Stop there.
4. No DOCTYPE control (the document is built by the server around your value): XInclude,
   `<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/hostname" parse="text"/></r>`.
5. Office and SVG files: unzip, add the entity to the inner XML, zip again with harmless content; upload as
   user-a only.
6. Nothing comes back (blind): the proof needs a receiver of ours. Look at the scope block of your task.
   - It shows a `support (oob): <oob host>` line: `bh-note canary`, then one external entity, referenced once,
     whose only URL is `https://<oob host>/c/<canary>`:
     `<!DOCTYPE r [<!ENTITY bho SYSTEM "https://<oob host>/c/<canary>">]><r>&bho;</r>`. One call, never any other
     data in the URL (no file, no parameter entity that reads one, no value of the target). Send it as one
     identity, the one you will name `--victim`; the other never sends the canary. Proof below.
   - No `support (oob)` line: `bh-note blocked oob-needed "<route>: blind XML entity"`.

## Proof
proof.json: `attack` = the request of step 3 (or step 1 when step 3 is filtered, with the claim reduced to
"entities are expanded"), expecting the file's content or the marker; `control` = the same document with the
entity declared and not referenced, expecting it absent. `--not-proven`: which files were not read.
Blind, with the scope's `support (oob)` host (step 6): control = the same document with the entity declared and
not referenced, N runs (0/N); then `bh-note finding "<title>" --severity <s> --class xxe --url <url>
--observation <canary> --victim <the identity that sent it> --attacker <the other> --control 0/N --summary
"<route, the one call, UTC time>" -e <file with the exact document>`. The host decides from what its listener
received; you never see it (the gate refuses that host to the sandbox).

## Never
- Nested or repeated entities (expansion bomb): denial of service.
- `http://` entities toward internal addresses, metadata endpoints or any host outside the scope; the one
  exception is the callback of step 6, `https://<oob host>/c/<canary>` and nothing else in it.
- Keys, configuration files, source code, or any second file once the first read proved it.
- A file that makes the server run something: stop, `bh-note blocked server-exec "<where, no content>"`.

## False positives
- The marker echoed because the field is echoed as text, entity unresolved (`&bhx;` comes back literally).
- A generic 400 on any DOCTYPE: the parser forbids DTDs, the control works.
- An error quoting your own input, not a path the server tried to open.
- (Strix) A DOCTYPE accepted but no entity resolved and no XInclude reached.
- (Strix) A filter or sandbox that writes the entity text back literally, with no file read.
- (Strix) A mock or stub that answers success without any file access (test or demo environments).
- (Strix) XML parsed only in the browser, never by the server.

## Watch
- An anomaly on one payload: one variant that keeps the syntax, then two close controls at most.
- A parser that accepts DTDs but returns nothing is a fact worth recording for when a receiver exists (a
  scope block without a `support (oob)` line).
