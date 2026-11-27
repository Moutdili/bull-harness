---
name: sqli
description: Use when a search, filter, sort or id parameter may reach a SQL query, or an answer shows a database error.
---
<!-- Source: card src/bh/cards/sqli.md (ours), plus the lines FUSIONS.md (skills audit, W3-C) drew from the Hermes
skill bug-bounty/nosql-injection (no licence stated). Modified: roles left free; removed: filter evasion,
out-of-band exfiltration, execution through the database, destructive payloads, time-based tests. -->
# SQL injection

## When
- Search, filter, sort or id parameters; database errors in responses.
- A value stored now and shown later in a report, an export or an admin list (second order).

## Do
1. By hand, one parameter at a time: does a quote or a parenthesis (`'`, `')`, `'))`) change the answer or raise a
   database error? `q '<url with the parameter>'`; authenticated parameters: `q -a <identity> '<url>'`; a body:
   `q -a <identity> -X POST -j '<body>' <url>`.
2. Then a boolean pair (`AND 1=1` vs `AND 1=2`, closed like step 1) and compare the two answers twice. For a sort
   or column parameter (no quotes): a valid column name vs a nonexistent one.
3. A point found: confirm with ONE read-only extraction (database version or the current database name).
4. Record what you tried: `bh-note cover "<METHOD /route>" sqli clean|suspect -e <raw body path>`.

## Proof
Data extracted through the injection (database version, a table or column name, a row the user cannot otherwise
read), or a boolean pair: a true and a false payload give consistently different answers on two runs.
proof.json: attack = the true payload, expecting a marker only the true answer holds (`contains`); twin control =
the same method and URL with the false payload, expecting that marker `absent`. The replay reads twice, which is
the "two runs". Then `bh-note finding "<title>" --severity <s> --class sqli --url <url> --proof proof.json
--summary "<...>" --not-proven "<...>" --counter "<...>" --severity-if "<...>" --severity-why "<...>"`.

## Never
- Time-based or stacked payloads, UPDATE/DELETE/INSERT, dumping tables (one value proves it).
- Payloads written to slip past a filter or a firewall: a refusal is an answer, record it.
- Extraction beyond the one value, or from a table of another user's data.

## False positives
- A database error tied to the payload is a lead, not a finding.
- An answer that changes for any odd character (a generic 400 or 500 for every quote) is input validation: try a
  non-SQL control string of the same length.
- `AND 1=2` returning nothing because the whole string was searched as text: then `AND 1=1` returns nothing too.
  The pair proves something only when the true payload gives the normal results.

## Watch
- An abnormal answer: first one variant that keeps the syntax (the same quote closed, the same parenthesis
  balanced), then two close witnesses at most (a neighbouring value, the request without the payload), before you
  widen anything.
- Second order: a value stored now and used in a query later (a profile field read by a report); the error shows
  on the page that reads it.
- Document databases and directory filters: skill `nosql-injection`.
- GraphQL arguments named `filter`, `where`, `order`: skill `graphql`.
