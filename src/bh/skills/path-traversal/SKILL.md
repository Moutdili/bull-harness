---
name: path-traversal
description: Use when a parameter names a file, template, page or path (download, view, include routes) and its value may reach the filesystem.
---
<!-- Source: card src/bh/cards/path-traversal.md (ours), plus the lines FUSIONS.md (skills audit, W3-C) drew from the
Hermes skill bug-bounty/lfi-rfi (no licence stated). Modified: rewritten for this harness; removed: log poisoning
and wrappers that lead to code running on the server, remote inclusion. -->
# Path traversal / local file read

## When
- Parameters naming files, templates or pages; download and view routes.
- A value that looks like a path or a file name in a query, a body or a cookie.

## Do
1. Find how the parameter maps to a file (extension added? directory prefixed?) with a legitimate value first.
2. Try `../` sequences toward a well-known readable file, then encoded forms (`%2e%2e%2f`, `..%2f`, `....//`);
   the Windows form (`..\..\windows\win.ini`); when the application appends an extension, a PHP stream filter
   returns the page's own source as Base64 (`php://filter/convert.base64-encode/resource=<page>`): one file.
3. Compare with the control: same value without the traversal.
4. Record it: `bh-note cover "<METHOD /route>" path-traversal clean|suspect -e <raw body path>`.

## Proof
The content of a file outside the served directory comes back (a known marker of a system file). proof.json:
attack = the traversal value, expecting the marker (`root:x:0:0` for `/etc/passwd`, `[fonts]` for `win.ini`);
twin control = the same method and URL with the legitimate value, expecting the marker `absent`.
`bh-note finding "<title>" --severity <s> --class path-traversal --url <url> --proof proof.json --summary
"<parameter, file read>" --not-proven "<...>" --counter "<...>" --severity-if "<...>" --severity-why "<...>"`.

## Never
- Read secrets beyond the marker that proves it (one known system file), write files.
- Wrappers or log files that lead to code running on the server: stop, `bh-note blocked server-exec "<where, no
  content>"`.
- A remote URL in the file parameter (that is the skill `ssrf`, under its rules).

## False positives
- The same page for every value (an error page or the default file).
- A file inside the served directory reached by another name (`./a/../b`): no boundary crossed.
- A marker that the page holds anyway (the word `root` in a menu).

## Watch
- An abnormal answer: first one variant that keeps the syntax (the same depth of `../`, the same extension), then
  two close witnesses at most (one level more or less, the legitimate value), before you widen anything.
- Archive imports that write paths (`../` in a ZIP entry): skill `file-upload`.
- XML parsers that read local files: skill `xxe`.
