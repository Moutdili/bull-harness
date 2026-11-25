---
name: msrc-ai-bug-bounty
description: Load when hunting or triaging AI vulnerabilities for Microsoft (MSRC AI bounty, Copilot, Zero Day Quest), when rating the severity of an AI flaw against the MSRC AI bug bar, or when deciding whether a prompt injection, data exfiltration or cross-user/cross-tenant leak is worth a report. Covers what pays, what does not, and what evidence MSRC expects.
---

# MSRC AI bug bounty (Copilot, Zero Day Quest)

Distilled from the MSRC talk "Zero Day Quest: Microsoft's Bug Bounty Program and AI Research"
(first ZDQ edition, late 2024) plus the harness notes in `docs/research/15-msrc-premier-programme.md`.
Line-level quotes and ambiguities: `references/talk-notes.md`.

**Authority order.** Live MSRC pages win: `microsoft.com/msrc/bounty-ai`, `bounty-terms`,
the Zero Day Quest page, and the AI bug bar (`aka.ms/aibugbar`). The talk is dated: its numbers
(x2 multiplier, $30,000 cap, "until mid January") belong to the 2024 edition. Lines marked
**(speaker only)** must be checked on those pages before they drive a decision.

## 1. What MSRC pays for in AI

- Scope named in the talk: `copilot.microsoft.com`, Copilot in the Edge sidebar, Copilot iOS and Android apps.
  Since Dec 2025 ("In scope by default", per doc 15), any Microsoft online service is eligible if impact is shown.
- Eligible: **Important or Critical** severity, in a category of the AI bug bar. Moderate/Low: no bounty, and no
  Researcher Recognition points either (points also start at Important).
- Range: doc 15 reads $100 to $30,000 for Copilot. The talk's "up to $30,000" already included the 2024 x2 doubling
  **(speaker only, dated)**.
- Award levers cited: industry averages, security maturity of the product, security impact, severity,
  and **report quality (low / medium / high)**. Quality is a lever the harness controls.
- Classic bugs inside an AI product (XSS, IDOR, SSRF, auth bypass) are judged by the online-services bug bar,
  not the AI one. The AI bar is explicitly non-overlapping.

## 2. Valid impact classes (AI bug bar)

Three top-level categories. Severity always hinges on **security impact** and **victim interaction**.

### Inference manipulation (one session, model unchanged)

- **Indirect prompt injection with a security impact.** The attacker is *not* the direct user: instructions arrive
  through a web page, an email, a document, a tool result. Impacts that count:
  - data exfiltration to an attacker-controlled endpoint (cited: page-borne injection makes Copilot render a
    markdown image whose URL carries the user's page or conversation data);
  - privileged action performed on the victim's behalf without their consent;
  - reading data the victim can see but the attacker cannot.
- Severity ladder (speaker): **zero-click** exfiltration or privileged action = **Critical**;
  needs a click or extra steps = "decrease the severity slightly"; no security impact = content issue, not paid.
- Input perturbation (adversarial examples): same rule, impact plus interaction.

### Model manipulation (changes the model for everyone)

- Model or data poisoning (training data, code, hyperparameters, architecture). Critical when the poisoned model makes
  decisions affecting other users; low when it only affects the attacker. Out of reach for the harness in practice.

### Inferential information disclosure (through the model's own interface)

| Type | Speaker's severity |
|---|---|
| Input extraction: reading another user's conversations/inputs | Important |
| Training data reconstruction | Important if training data was highly confidential; lower if public |
| Attribute / membership / property inference | Lower than reconstruction |
| Model stealing (weights, architecture) | Low (open model) to Critical (highly confidential model) |

### Cross-user and cross-tenant

- The talk gives **no** cross-tenant example. Deduction: a leak of another user's or tenant's data through Copilot is
  either input extraction (AI bar) or information disclosure (online-services bar); both need **two identities you own**
  (attacker, victim) to prove. Verify classification on the bug bars.

## 3. What does not pay

- Prompt injection **without** security impact: changed tone, wrong answer, jailbreak, harmful content =
  "content related issue". Report through the same portal if wanted, but no bounty.
- **System prompt extraction.** Removed from the bar: "The system prompt is not actually seen as as a secret."
  (Doc 15 confirms for Copilot.) Careful: the transcript once says "input extraction is now not in scope";
  context shows the speaker meant *prompt* extraction. Other-user input extraction stays Important.
- Direct prompt injection by the user against their own session with no effect on anyone else
  (doc 15: injection without impact on another user is out of scope).
- Hallucinated "leaks": model output that cannot be proven to be real data.
- Moderate or Low severity anything. Self-only impact (attacker affects only themselves).

## 4. How MSRC rates severity (AI bug bar)

1. Map the finding to a bar category (AI bar, or classic online-services bar for non-AI bugs).
2. Ask "what security impact?": exfiltration, unauthorized action, disclosure of whose data, of what classification.
3. Ask "how much victim interaction?": zero-click > one click > multi-step.
4. Ask "who is affected?": other users / tenants > attacker only.
5. Data classification drives disclosure classes (public < confidential < highly confidential).

Bar history to remember: published Aug 2023, updated Jun 2024. Two lessons the authors cite:
"prompt injection requires a security impact"; "prompt extraction is not a vulnerability".
Re-read `aka.ms/aibugbar` before each campaign: it is versioned and the talk says it will change.

## 5. Zero Day Quest

What the talk says (2024 edition, **speaker only**):
- Public research challenge with a fixed window ("running until mid January" then).
- All AI bounty rewards **doubled** during the challenge.
- MSRC ran several training sessions for it (this one and at least one earlier).

What doc 15 recorded from the official pages (2025 edition):
- Two tracks: open Research Challenge (**+50 %** for Critical or high-impact scenarios, cloud and AI)
  and an invitation-only Live Hacking Event (45 researchers, **selected by amounts earned**).
- Challenge 4 Aug to 4 Oct 2025; no later edition announced when read. Outside a window, normal programs apply.

Not covered by the talk at all: selection criteria detail, multiplier table, scoring. Check the ZDQ page.

Speaker advice for researchers (applied to the harness):
- Hunt at "the intersection between the large language model and the system that's hosting it":
  rendering of model output, tool/plugin calls, retrieval sources, actions. Not the model alone.
- Expected growth areas: **agents / agentic systems**, multimodal inputs.
- Injection vectors vary: hidden page text, email content, non-printable characters. Map every channel that feeds
  "additional context" to the model.
- Know the expected behavior first (learn.microsoft.com, feature and admin flags) so a deviation is provable.
- Practice on LLMail-Inject-style challenges and read public writeups (e.g. Embrace the Red) before live targets.
- Defenses in place: Prompt Shields; expect them, and treat a bypass as only the first half of a finding.

## 6. Proof and report MSRC expects

Submit via the MSRC Researcher Portal (the talk's short link was transcribed "aka.ms/secure-ai"; unverified).
Form: vulnerability type, affected product, PoC (video, screenshots, or written steps).

AI-specific items the speakers asked for. Make each one a required field in the harness report:

| Item | Harness rule |
|---|---|
| Exact URL or app (web, Edge sidebar, iOS, Android) and version | Record the surface and build per finding |
| Setup choices made in Copilot (settings, modes, plugins, account type) | Snapshot settings of both test accounts |
| Full text of every prompt entered | Store verbatim, not paraphrased |
| Clear evidence: screenshots, video, **conversation ID** | Capture the conversation ID of every run |
| Reproduction rate ("1, 10 or 100 times") | Run N times, report k/N |
| Proof it is not a hallucination | Independent side-channel evidence (see below) |

Non-hallucination proof (deduction, not from the talk): show an effect outside the model's text,
e.g. a request logged on a collector you own carrying data that only the victim account holds,
or a state change visible from the victim account. A model *saying* it leaked data proves nothing.

Report hygiene:
- Impact statement first: who is the victim, what crosses which boundary, how much interaction.
- Victim must be your own second account or tenant. Never real users' data (bounty-terms, doc 15).
- Incomplete is acceptable: "just report the information that you have", then add vectors or repro counts
  through the portal chat or the case email thread.
- A human reviews every report before submission (MSRC may suspend for unreviewed AI-generated volume, doc 15).
- Questions: bounty@microsoft.com.

## 7. Common pitfalls (cited or directly implied)

- Reporting a jailbreak or output manipulation as "prompt injection": no security impact, no bounty.
- Reporting system prompt disclosure. Not a vulnerability.
- Direct injection where attacker = victim. The attacker must not be the direct user.
- No conversation ID, no prompt text, no repro rate: lower report quality, lower award, slower triage.
- Claiming a leak that may be hallucinated.
- Relying on talk numbers (x2, $30,000, dates) without checking the current ZDQ and bounty-ai pages.
- Expecting easy wins: the speaker said heavy pre-launch testing means "I don't expect that you'll find lots of things".
- Testing beyond PoC, on others' data, or with high-volume automation (doc 15 rules; not from the talk).

## 8. Harness checklist before a Copilot/AI campaign

1. Re-read bounty-ai, bounty-terms, ZDQ page, AI bug bar; note date and version in the run log.
2. Two owned identities (attacker, victim), ideally in separate tenants for cross-tenant claims.
3. Enumerate context channels that reach the model for the victim (pages, mail, files, connectors, tools).
4. For each candidate: name the bar category, the impact, the interaction count, the affected party.
   Drop anything that is content-only or self-only.
5. Capture: surface + version, settings, verbatim prompts, conversation IDs, k/N repro, side-channel proof.
6. Human review, then portal submission. Follow up in the case thread with new evidence.
