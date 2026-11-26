---
name: msrc-ai-bug-bounty
description: Load when hunting or triaging AI vulnerabilities for Microsoft (MSRC AI bounty, Copilot, Zero Day Quest), when rating the severity of an AI flaw against the MSRC AI bug bar, or when deciding whether a prompt injection, data exfiltration or cross-user/cross-tenant leak is worth a report. Owns what pays, what does not, and the report format MSRC expects for all MSRC AI skills.
---

# MSRC AI bug bounty (Copilot, Zero Day Quest)

Distilled from the MSRC talk "Zero Day Quest: Microsoft's Bug Bounty Program and AI Research"
plus the harness notes in `docs/research/15-msrc-premier-programme.md`.
Line-level quotes and ambiguities: `references/talk-notes.md`.

This skill is the **single home** of "what pays", severity and the report format. Related skills point
here: `msrc-copilot-studio-research` (Copilot Studio / Power Platform surface), `ai-red-team-pyrit`
(injection workflow, payload delivery). Canary in all three: `BH-SECRET-<16 hex>`, printed by `bh-note canary`
(the gate looks for it in its own traffic).

Tags: **[talk]** = said in this talk; **[PyRIT talk]** = the MSRC PyRIT webinar (2 Dec 2024);
**[doc 15]** = official pages as summarised in doc 15; **[deduction]** = ours, not said.

**Dating [deduction].** Probably the first ZDQ edition, late 2024: the bar was "updated ... in June of
this year, 2024", the challenge ran "until mid January". The PyRIT webinar of 2 Dec 2024 announces a
follow-up "AI Bug Bar" session on 17 Dec 2024, which may be this talk (not confirmed).

**Authority order.** Live MSRC pages win: `bounty-ai` (path `microsoft.com/msrc/bounty-ai`, not verified
here), `bounty-terms`, the Zero Day Quest page, and the AI bug bar (`aka.ms/aibugbar`, said in the talk,
not opened here). The talk's numbers (x2 multiplier, $30,000 cap, "until mid January") belong to the 2024
edition. Re-reading these pages is an **orchestrator task before the run**: the hunter has no web.

## 1. What MSRC pays for in AI

- Scope named in the talk: `copilot.microsoft.com`, Copilot in the Edge sidebar, Copilot iOS and Android apps.
  Since Dec 2025 ("In scope by default" [doc 15]), any Microsoft online service is eligible if impact is shown.
- Eligible: "vulnerabilities that are assessed as important or critical severity in the categories that are
  detailed on our AI Bugbar" [talk]. Researcher Recognition points also start at Important [talk].
  That Moderate/Low gets nothing at all is our reading [deduction].
- Range: doc 15 reads $100 to $30,000 for Copilot. The talk's "up to $30,000" already included the 2024 x2
  doubling [talk, dated].
- Award levers cited: industry averages, security maturity of the product, security impact, severity [talk],
  and **report quality (low / medium / high)** [talk]. Quality is a lever the harness controls.
- The AI bar complements the online-services and Windows bars, "nothing overlapping between them" [talk].
  That classic bugs inside an AI product (XSS, IDOR, SSRF) are judged by the online-services bar is our
  reading [deduction]; the talk only says "a lot of those things are already covered in our existing bug bars".

## 2. Valid impact classes (AI bug bar)

Three top-level categories [talk].

### Inference manipulation (one session, model unchanged)

- **Indirect prompt injection with a security impact.** "the attacker is not the direct user of of the
  model" [talk]. Vectors cited: a web page, an email (hidden with "non-printable characters"), a document
  [talk]; a tool result is our extension [deduction]. Impacts that count [talk]: "a zero-click
  exfiltration of data, or performing some privileged action on behalf of the user". Reading data the
  victim can see and the attacker cannot is how *we* frame exfiltration between two accounts [deduction].
- Cited example, **already fixed**: page-borne injection makes Copilot render a markdown image whose URL
  carries page or conversation data. "all the vulnerabilities that we talked about in this talk today have
  been reported to MSRC and have been fixed" [talk]. Do not replay it; look for a **variant** (another
  renderer, another output channel: link preview, tool call, file write, mail sent).
- Severity [talk]: zero-click exfiltration or privileged action = **Critical**; if the user must "click on
  a link or or go through one or more steps, that would decrease the severity slightly"; no security
  impact = content issue, not paid.
- Input perturbation (adversarial examples): severity depends on security impact and victim interaction [talk].

### Model manipulation (changes the model for everyone)

- Model or data poisoning. Critical when the poisoned model makes decisions affecting other users; "a much
  lower severity" when only the attacker is affected [talk]. Out of reach for the harness in practice.

### Inferential information disclosure (through the model's own interface)

Severity here hinges on **data classification** and who is affected, not on victim interaction.

| Type | Speaker's severity [talk] |
|---|---|
| Input extraction: reading "somebody else's uh conversations with with co-pilot" | Important |
| Training data reconstruction | Important if highly confidential; lower if public |
| Membership inference | "doesn't go up to as high a severity as something like training data reconstruction" |
| Attribute / property inference | cited, no level given |
| Model stealing (weights, architecture) | "ranges from low all the way up to to critical" (open model -> highly confidential model) |

### Cross-user and cross-tenant

- The talk gives **no** cross-tenant example. [deduction] A leak of another user's or tenant's data through
  Copilot is either input extraction (AI bar) or information disclosure (online-services bar); both need
  **two identities we own** (attacker A, victim B). Verify on the bars.

## 3. What does not pay

- Prompt injection **without** security impact: changed tone, wrong answer, harmful content = "content
  related issue" [talk]. Jailbreaks: "you don't get bounties for convincing Chat GPT to tell you how to make
  meth" [PyRIT talk]. Reportable through the same portal, no bounty.
- **System prompt extraction.** Removed from the bar: "The system prompt is not actually seen as as a
  secret." [talk] (doc 15 confirms for Copilot.) The transcript once says "input extraction is now not in
  scope"; context shows *prompt* extraction was meant. Exception: "if they apply to a specific user and
  there's confidential information there, please by all means send us a case" [PyRIT talk].
- Direct injection by the user against their own session, attacker = victim [talk, doc 15].
- Hallucinated "leaks": output that cannot be proven to be real data.
- Self-only impact. Moderate or Low severity.
- **Rate-limit bypass: do not hunt it.** Looking for it means exceeding the limit. If seen by accident,
  note it: "If you're able to bypass the rate limiting, by all means uh let us know but don't use that
  that capability to perform any denial of service testing" [PyRIT talk].

## 4. How MSRC rates severity (AI bug bar)

1. Map the finding to a bar category (AI bar, or classic online-services bar for non-AI bugs [deduction]).
2. "What security impact?": exfiltration, unauthorized action, disclosure of whose data, of what classification.
3. For inference manipulation, "how much victim interaction?": **zero-click**, then **any interaction**
   (a click or more steps: "decrease the severity slightly") [talk].
4. "Who is affected?": other users / tenants > attacker only.
5. Data classification drives disclosure classes (public < confidential < highly confidential).

Bar history [talk]: published Aug 2023, updated Jun 2024. Two lessons: "prompt injection requires a
security impact"; "prompt extraction is not a vulnerability".

## 5. Zero Day Quest

What the talk says (2024 edition, dated): public research challenge "running until mid January" then;
"we are doubling all of our AI book bounty rewards" (= bug bounty); several training sessions.

What doc 15 recorded (2025 edition): Research Challenge (**+50 %** for Critical or high-impact scenarios,
cloud and AI) and an invitation-only Live Hacking Event (45 researchers, **selected by amounts earned**);
challenge 4 Aug to 4 Oct 2025; no later edition announced when read. Outside a window, normal programs apply.

Speaker advice applied to the harness [talk unless tagged]:
- Hunt at "the intersection between the large language model and the system that's hosting it":
  rendering of model output, tool/plugin calls, retrieval sources, actions.
- Expected growth areas: agents / agentic systems, multimodal inputs.
- Map every channel that feeds "additional context" to the model (page text, email, documents).
- Know the expected behavior first (learn.microsoft.com, feature and admin flags).
- Practice on LLMail-Inject-style challenges and public writeups before live targets.
- Defenses in place: Prompt Shields; TaskTracker (open-source injection detector) cited as research.
  A filter bypass is only the first half of a finding [deduction].
- Content issues "can, uh, eventually lead to more security vulnerabilities": note them, do not file them
  as security bugs.
- "I don't expect that you'll find lots of things in in in these places."

## 6. Proof and report (single source for the three MSRC AI skills)

Submission: MSRC Researcher Portal, reached from the official bounty-ai page. **Do not use the short
links** heard in the talks ("aka.ms/secure-ai" here, "aka.ms/secure-at" in the PyRIT talk): they disagree
and neither was checked. Form [talk]: vulnerability type, affected product, PoC ("a video or screenshots
or written steps to reproduce"). "a high quality report will include screenshots, steps to reproduce and
a proof of concept" [PyRIT talk].

AI-specific items the speakers asked for [talk], each a field of the harness report:

| Item | Harness rule |
|---|---|
| "the exact URL or application of co-pilot uh service that you're interacting with" | Record surface and build per finding |
| "any choices ... you made when setting up your co-pilot service and including the text of any prompts" | Snapshot settings of A and B; prompts verbatim |
| Clear evidence: screenshots, video, "or even the conversation ID" | Conversation ID of every run when the UI shows one |
| Reproduction rate: "one one time or 10 times or 100 times" | Run N times, report k/N (non-deterministic target) |
| "if possible at all, ... proof that the issue isn't a result of a hallucination" | Optional per the talk; see below |

Non-hallucination proof [deduction], in this order, because `bh-oob` does not exist (issue 31 open):
1. **Effect visible from A's account**: a canary `BH-SECRET-<16 hex>` (from `bh-note canary`, planted by us in
   B's data) appears in a response A receives, in A's mailbox, or in an object A owns.
2. **Effect inside B**: an action executed in B's account that only A's planted content asked for (mail
   sent, file written, setting changed), seen as B, with a control run without the poisoned source.
3. **Request leaving B's browser**: `bh-browse` aborts and counts off-host requests per host in its
   summary; a counted request to a host named only in A's payload is a lead (whether the full URL lands in
   raw `har.json` is not verified).
4. A receiver we own: needs `bh-oob`. Until then `bh-note blocked oob-needed "<what and where>"`.
A model *saying* it leaked data proves nothing.

Report hygiene:
- Impact statement first: who is the victim, what crosses which boundary, how much interaction.
- Victim = our own second account or tenant. Never real users' data [doc 15].
- Incomplete is acceptable: "just report the information that you have" [talk], then add vectors or
  repro counts through the portal chat or the case email thread [talk].
- A human reviews every report before submission (MSRC may suspend for unreviewed AI-generated volume) [doc 15].
- Questions: bounty@microsoft.com [talk].

## 7. Common pitfalls

- Reporting a jailbreak or output manipulation as "prompt injection": no security impact, no bounty.
- Reporting system prompt disclosure (unless user-specific and confidential).
- Direct injection where attacker = victim.
- Replaying the fixed markdown-image exfiltration as is.
- No conversation ID, no prompt text, no repro rate: lower report quality, lower award, slower triage.
- Claiming a leak that may be hallucinated.
- Relying on talk numbers (x2, $30,000, dates) without the current ZDQ and bounty-ai pages.
- Testing beyond PoC, on others' data, or with high-volume automation [doc 15]. Server-side execution:
  stop at PoC ([PyRIT talk]; gesture in `ai-red-team-pyrit` §5).

## 8. Checklist before a Copilot/AI campaign

1. Orchestrator, before the run: re-read bounty-ai, bounty-terms, ZDQ page, AI bug bar; note date and version.
2. Two owned identities (A, B), in separate tenants for cross-tenant claims.
3. The chat is driven in the persistent browser only (`bh-web`, scope with `websockets: true` and the challenge
   host as `passthrough`); the operator passes the Turnstile challenge by hand. Never look for another path to
   send prompts (no direct websocket, no API call carrying a prompt): that would skip the challenge.
4. Enumerate context channels that reach the model for B (pages, mail, files, connectors, tools).
5. For each candidate: bar category, impact, interaction, affected party. Drop content-only or self-only.
6. Capture: surface + version, settings, verbatim prompts, conversation IDs, k/N, proof from the list in §6.
7. Human review, then portal submission. Follow up in the case thread with new evidence.
