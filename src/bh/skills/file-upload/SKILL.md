---
name: file-upload
description: Use when a route accepts a file (upload, avatar, import, attachment, media) and you can see where and how the file is served back.
---
<!-- Source: card src/bh/cards/file-upload.md (ours), plus the lines FUSIONS.md (skills audit, W3-C) drew from the
Hermes skills bug-bounty/file-upload-rce, csv-formula-injection and xxe-injection (no licence stated). Modified:
roles left free; removed: server-side code files, server configuration overrides, spreadsheet command payloads. -->
# File upload

## When
- Upload, avatar, import, attachment or media routes.
- An import of CSV, XML, ZIP or an office document; an export that writes user fields into a file.

## Do
1. Upload a harmless file as one of our identities and find where and how it is served back (URL, Content-Type,
   Content-Disposition, domain): `q -a <owner> -i -n 200 <file url>`.
2. Content-type confusion: SVG or HTML with a benign marker served inline from the main domain. The SVG holds only
   `<svg xmlns="http://www.w3.org/2000/svg"><script>window.__bhxss='bhx12345'</script></svg>`; check it with
   `bh-browse '<file url>' --as <owner> --xss bhx12345`, once.
3. Name handling: path characters in the filename (`../`, `;`, NUL); check where it lands, do not overwrite
   anything. Extension handling with a harmless text file: a double extension, mixed case, a trailing `;`; look only
   at the type and disposition it is served with.
4. Import features (CSV, XML, ZIP): formula injection, XXE markers, archive paths, with benign content. Exports: a
   field holding `=1+1` that comes back at the start of a CSV cell; many programs exclude it, check before
   recording. XML inside (SVG, DOCX, XLSX): skill `xxe`.
5. Access: `qq <file url>`: the owner 200, the other identity and anonymous refused (skill `idor`).

## Proof
An uploaded file served back in a way that runs, or one the other identity can fetch. Script: proof.json whose
attack step holds `"browse": {"xss": "<marker>"}` on the file URL and expects
`{"contains": ["xss CONFIRMED (marker <marker>)"]}`; control = the same step with another marker, role `control`,
expecting `{"absent": ["xss CONFIRMED"]}` (say in `--not-proven` that this control only shows the script is
yours). Access: proof.json as in the skill `idor`. `bh-note finding "<title>" --severity <s> --class file-upload
--url <file url> --proof proof.json --summary "<...>" --not-proven "<...>" --counter "<...>" --severity-if
"<...>" --severity-why "<...>"`. Code running on the server: stop, `bh-note blocked server-exec "<where, no
content>"`.

## Never
- Upload executable payloads, web shells or large files; never overwrite another user's file.
- A file that does more than set the marker, or that reaches a third party when opened.
- Leave test files behind: delete them as the owner at the end.

## False positives
- Storing an arbitrary file alone is not a vulnerability.
- An SVG or HTML served with `Content-Disposition: attachment`, or from a sandbox domain without the session.
- A formula that comes back quoted (`'=1+1`) or not at the start of the cell.

## Watch
- The served host decides the impact: a separate content domain runs script without the app's session.
- An image re-encoded by the server drops what you hid in it: compare sizes before and after.
