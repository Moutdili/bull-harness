---
name: scanner-playbook
description: Use when the program allows automated scanners and you want a first automated pass (hidden paths, parameters, templates, SQL, reflected XSS) before the method by hand.
requires: scanners
---
<!-- Source: the scanner lines that W3-C moved out of the class cards (src/bh/classes.py `scan`, ours), plus the
list of hidden parameters FUSIONS.md (skills audit, W3-C) drew from the Hermes skill bug-bounty/parameter-mining (no
licence stated), to try by hand. Modified: written for this harness's wrappers only; removed: any scanner the image
does not hold, wordlists of credentials, time-based and out-of-band options. -->
# Scanner playbook (programs that allow scanners only)

## When
- The scope says `scanners_allowed: true`. A wrapper that answers "this program forbids automated scanners"
  means it does not: stop here and use the class skills by hand.
- After mapping (`bh-crawl`), on the origins of your scope block, one wrapper at a time.

## Do
1. Hidden paths: `bh-content <origin>` (`--wordlist <file>` for a list of your own). Hits go to the skill
   `info-disclosure`. Candidates also come from the hits of `bh-content` and `bh-scan`.
2. Templates: `bh-scan <origin>` (`--deep` adds exposures and medium misconfigurations, slow). A hit is a lead.
3. Hidden parameters: `bh-params <url>`. Then by hand, one request each on a route that matters, compared with the
   answer without it (size, status, one field): `debug`, `test`, `admin`, `redirect`, `callback`, `fields`,
   `expand`, `include`, `sort`, `order`; e.g. `q -a <identity> -n 400 '<url>?debug=1'`.
4. SQL: `bh-sqli '<url with the parameter>'` (`--data` for a body, `--as user-a` for an authenticated one) runs
   Boolean/Error/Union only, never time-based; a point it finds is confirmed by hand with ONE read-only extraction.
   Method: skill `sqli`.
5. Reflected XSS: `bh-xss '<url?param=x>'` for the reflected cases, before the method by hand.
   Method: skill `xss`.
6. Writes across identities: `bh-authz --write-own` also sends a cross-identity PATCH on your own objects (skill
   `idor`); read `raw/authz-*/proof.json` after it.
7. Active scan of one origin: `bh-zap <url> --as <identity> --active` (passive rules only without `--active`).
8. Record what each wrapper covered: `bh-note fact "<wrapper> <origin>: <n> hits" -s "<raw path>" -k recon`.

## Proof
A scanner hit is never a proof. Each hit is confirmed by hand in its class skill, with that skill's proof.json and
its twin control (the same request without the payload, or as an identity without the right).

## Never
- Run a wrapper the program refuses, or look for another way to run one.
- Time-based, stacked or out-of-band options; credential lists; loops over ids or codes.
- More than one wrapper at a time: the gate's rate covers all of your traffic.

## False positives
- The same 200 page on every path (the app shell, a soft 404).
- Template hits on a version banner alone; a reflected parameter that comes back HTML-encoded.
- A SQL "injection" that is a generic error for every odd character (skill `sqli`, False positives).

## Watch
- Wrappers leave their output under `raw/`: read the file, not only the summary line.
- A hidden parameter that changes the answer is a lead for the class it points at (`redirect` and `callback`:
  skill `open-redirect`; `fields`, `expand`, `include`: skill `idor`; `sort`, `order`: skill `sqli`).
