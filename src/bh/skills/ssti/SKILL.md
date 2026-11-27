---
name: ssti
description: Use when a value you send comes back rendered by a server template (preview, e-mail or PDF template, custom field, report title). Fingerprints the engine with arithmetic and stops at the proof.
---
<!--
Source: strix/skills/vulnerabilities/ssti.md, Strix (https://github.com/usestrix/strix), Copyright 2025 OmniSecure
Inc., Apache License 2.0.
Also: inputs/skills-audit/FUSIONS.md, section "Classes T41", row "SSTI" (Hermes ssti-*, no licence stated):
arithmetic fingerprint `{{7*7}}`, `{{7*'7'}}`, `${7*7}`, `<%= 7*7 %>`; stop at the proof, `blocked server-exec`.
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form; kept: the probe table, the evaluation vs
reflection line and the false positives; removed: every sandbox escape, class walk, reflection gadget and
command-execution payload per engine, object-access probes (`self`, `config`, `request`), out-of-band and sleep
validation, file writes.
-->

# Server-side template injection

## When
- A field you control is rendered by the server into a page, a mail, a PDF or an export: a preview pane, a
  notification or invoice template, a custom field label, a report title, a tenant's "edit your template".
- A benign string comes back verbatim in that output (first check: plain `bhx12345`).

## Do
1. Plain marker first: `bhx12345` in the field, then read where it is rendered. No rendering seen: not here.
2. Arithmetic, one probe per request, a product nobody types by chance (`91829*7` = 642803):
   | Probe | Renders | Family |
   |---|---|---|
   | `{{91829*7}}` | `642803` | Jinja2, Twig, Nunjucks |
   | `{{7*'7'}}` | `7777777` (Jinja2) or `49` (Twig) | tells Jinja2 from Twig |
   | `${91829*7}` | `642803` | Freemarker, Velocity, Spring EL, JSP EL, Thymeleaf |
   | `<%= 91829*7 %>` | `642803` | ERB, EJS |
   | `#{91829*7}` | `642803` | Pug, some Ruby contexts |
   Stop at the first that evaluates.
3. Confirm with a second product (`{{91829*8}}` = 734632): two different results rule out a coincidence.
4. The proof is there. Write it, record the finding, then stop:
   `bh-note blocked server-exec "ssti <engine family> at <route>"`. Nothing after it.
5. Nothing evaluates: `bh-note fact "<route> <field>: template syntax rendered literally" -k dead-end --why technical`.

## Proof
proof.json; for a stored field the write is a `setup` step on your own object:
- `attack`: the field holding `{{91829*7}}` (the probe of step 2 that evaluated), expecting `642803` in the
  rendered output;
- `control`: the same request with `91829*7` without the template delimiters, expecting `642803` absent.
In `--not-proven`: "no object or runtime access attempted; stopped at evaluation".

## Never
- Anything past arithmetic: no `self`, `config`, `request`, class or module walk, no reflection, no command, no file
  read or write, no sleep, no callback.
- A probe in a template other people receive (a shared e-mail template, a public page): only a field of your own
  account, rendered for your own identity.
- A loop over a polyglot list. One probe per family, in the order above.

## False positives
- (Strix) Template syntax shown literally (`{{91829*7}}` comes back as typed): that may be XSS-shaped, not SSTI.
- (Strix) Client-side template engines (Angular, Vue, Mustache in the browser): client-side template injection,
  an XSS question (card `xss`), not server execution.
- (Strix) Templates rendered at build time only, with no user input reaching the build.
- (Strix) An HTML-escaped output that hides the evaluation: use the numeric probe, read the number.
- A number that was already on the page (a price, an id): check the control.

## Watch
- An evaluated product in a mail you cannot read in the sandbox: `bh-note blocked other "ssti probe rendered in
  a mail: <route>"`; the operator reads it.
- `blocked server-exec` ends the segment and parks the program until the operator lifts it: that is the purpose.
