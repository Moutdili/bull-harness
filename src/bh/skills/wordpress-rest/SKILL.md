---
name: wordpress-rest
description: Use when a target runs WordPress (`/wp-json/`, `wp-content` in the HTML). Reads the REST index for plugins and custom types, and checks whether a custom type lists private submissions.
---
<!--
Source: hermes/.archive/wordpress-security-audit/SKILL.md; merged from hermes/security/bug-bounty-workflow-automation/references/wordpress-api-recon.md and section titles of hermes/security/bug-bounty-hacking (Hermes Agent, MIT) (the other two: no author or licence stated).
Modified: translated; DNS lookups, GitHub searches, login pages, 100-record reads and real target names removed; minimal-read and stop rules are ours.
Role: hunter. Technology skill (plan item D21).
modified (bull-harness W3-H): the two unmeasured lines (`X-WP-Total`, `?rest_route=/`) removed (not measured);
step 7 no longer reads the authors list (user enumeration).
-->

# WordPress REST surface

## When
The HTML references `wp-content` or `wp-json`, or `q <origin>/wp-json/` answers JSON.

## Do
1. Index, one request: `q -n 4000 <origin>/wp-json/`. The `namespaces` list names every plugin that exposes
   REST routes: an inventory without any scan. `bh-note fact "wp namespaces" -s "<list>" -k recon`.
2. Types, one request: `q -n 4000 <origin>/wp-json/wp/v2/types`. Each entry has a `rest_base`. Standard types
   (posts, pages, media) are public content. Custom types named like forms, results, entries, submissions,
   orders or messages are the leads.
3. Per custom type, at most 5 types, the smallest read:
   `q -i -n 300 '<origin>/wp-json/wp/v2/<rest_base>?per_page=1'`.
   - 401 or 403 (`rest_forbidden`): closed. Dead end, record it.
   - 200 with a record: read only enough to tell public content from a private submission.
4. A record that holds a real person's data (name, mail, phone, message): one read proved it. Stop, do not
   read it again, `bh-note blocked third-party-data "<route, no content>"`. The operator decides the report.
5. Versions as facts, one request each: `/readme.html`, a plugin's `/wp-content/plugins/<slug>/readme.txt`
   ("Stable tag"). A version is a fact for the board, never a finding (skill `false-positive-traps`).
6. Leftovers, single requests to names the installed plugins imply (a backup plugin in the namespaces means
   its backup directory may exist), and at most 8 paths in a segment: backup directories under
   `/wp-content/`, `wp-config.php.bak`, `wp-config.php~`. Ask for headers only (`q -X HEAD`): a 200 with a
   size is the lead.
7. Authors list (`/wp-json/wp/v2/users`): user enumeration, excluded almost everywhere and other people's
   data. Do not request it.

## Proof
- A private custom type readable without a session: `attack` with `"as": null` on the `per_page=1` URL
  expecting 200 and a field name of the submission type (not a person's value); `control` on a closed type
  or on the same route of a protected method. `--not-proven`: how many records exist beyond the first.
- An exposed backup or config: the header answer (status, type, size). Never the content.

## Never
- Download a backup archive or a configuration file. Existence and size are the proof.
- Read a second record, page through a collection, or use `per_page` above 1.
- The login page, XML-RPC, password guessing, plugin exploit code.
- More not-found answers than the gate tolerates on a program without scanners (it pauses the origin).

## False positives
- A 200 HTML page on a missing file (theme 404 served as 200): check the content type and size.
- Public content exposed by design through the REST API.
- A plugin version with a known CVE: a lead to check against the exact version, not a report.

## Watch
- Custom fields plugins add data to public types: a public post can still carry a private field.
