# Talk notes: "Zero Day Quest: Microsoft's Bug Bounty Program and AI Research" (MSRC)

- Source: MSRC YouTube, https://www.youtube.com/watch?v=cvH9M_C7BR4, 61 min 11 s.
- Transcript: automatic (Gemini 2.5 Flash), file
  `~/.claude/uploads/f344491a-9dfc-4dec-a393-2cfb685d99b9/c8ef8dee-02_zero-day-quest-bug-bounty-ai-research.txt`.
  It has no timestamps. Positions below are `L<n>` = line of `fold -s -w 200 <file> | cat -n`,
  and `~m<min>` = minute estimated linearly from the line (309 lines for 61 min). Treat minutes as +/- 2 min.
- Speakers: Aiden (host, MSRC AI security), Lynn (PM, researcher incentives, runs the bounty programs),
  Andrew "Pavert" (transcribed; probably Andrew Paverd), research manager, AI vulnerabilities and mitigations,
  lead author of the AI bug bar.
- Tags: **[A]** = asserted by a speaker. **[D]** = my deduction, not said. **[?]** = ambiguous or likely mistranscribed.

## 0. Dating (read first)

- **[D]** The talk is from the **first** Zero Day Quest edition (late 2024), not the current one:
  bug bar "updated ... in June of this year, 2024" (L65, ~m13); challenge "running until mid January" (L10, ~m2);
  Ignite announcements "recent" (L223, ~m44); LLMail-Inject announced "just a few days ago" (L168, ~m33).
- **[D]** Every number (doubling, $30,000 cap, dates) is therefore an edition-2024 fact. The harness note
  `docs/research/15-msrc-premier-programme.md` (read 2026-11-25) records a 2025 edition with **+50 %**, not x2,
  and the "In scope by default" change (Dec 2025). Always prefer the live MSRC pages.

## 1. Programme and money

- **[A]** "we are doubling all of our AI book bounty rewards as part of Zero Day Quest" (L10, ~m2).
  "book bounty" = bug bounty (transcription error, recurs).
- **[A]** Overall Microsoft bounties: "we offer bounty awards up to $250,000" (L34-35, ~m7), claimed 2-10x industry average.
- **[A]** Award pricing factors: industry averages, "security maturity of the product or service", security impact,
  severity (L35-36, ~m7).
- **[A]** "only a portion of the reports that are submitted to the MSRC um are actually going to be eligible for bounty awards" (L39, ~m8).
- **[A]** July 2023 to June 2024: "$16.6 million to 343 researchers across uh 55 countries" (L44-45, ~m9).
  The speaker says "July 2023 to July uh June 2024" **[?]**.
- **[A]** AI bounty focuses on Microsoft Copilot; doubled "to now have awards up to $30,000" (L51-52, ~m10).
- **[A]** Scope examples: "copilot.microsoft.com, the Copilot AI experience that's in your uh Microsoft Edge browser,
  um or the iOS or Android mobile applications" (L52-53, ~m10).
- **[A]** Eligibility: "vulnerabilities that are assessed as important or critical severity in the categories that are
  detailed on our AI Bugbar" (L55, ~m11).
- **[A]** Non-monetary: Researcher Recognition Program, points for Important and Critical reports, quarterly leaderboards,
  annual MVR list (L26-30, ~m5-6).
- **[A]** Report quality is a bounty lever: "there's uh low, medium and high report qualities there" (L237, ~m47).

## 2. The AI bug bar

- **[A]** Public at "aka.ms/aibugbar"; first published August 2023, updated June 2024 (L65-66, ~m13).
- **[A]** It complements the existing online-services and Windows bug bars, "nothing overlapping between them" (L62, ~m12).
  Classic web bugs in an AI product are judged by the classic bars **[D]**.
- **[A]** Three new top-level categories (L105-112, ~m21-22):
  - inference manipulation: manipulates one inference/session, model unchanged;
  - model manipulation: changes the underlying model, affects all its users;
  - inferential information disclosure: information inferred through the model's own inference interface.

### Inference manipulation

- **[A]** Prompt injection = "the ability to inject instructions that cause the model to generate some unintended output
  that leads to a specific security impact" (L114, ~m22).
- **[A]** The attacker is not the direct user: "the attacker is not the direct user of of the model" (L115, ~m22-23).
- **[A]** Critical: "a zero-click exfiltration of data, or performing some privileged action on behalf of the user
  without them having to do anything" (L117, ~m23).
- **[A]** User interaction (click a link, one or more steps) "would decrease the severity slightly" (L118, ~m23).
- **[A]** No security impact = "content related issue. That's not currently in scope for our current um AI bounty program"
  (L119-120, ~m23); still reportable through the same process.
- **[A]** Input perturbation (adversarial examples / model evasion): severity depends on security impact and victim
  interaction (L123-125, ~m24).

### Model manipulation

- **[A]** Model or data poisoning: tampering with architecture, training code, hyperparameters or training data
  (L127-128, ~m25). "tempering" in the transcript = tampering **[?]**.
- **[A]** Critical if the poisoned model makes decisions affecting other users; much lower if only the attacker (L129-130, ~m25-26).

### Inferential information disclosure

- **[A]** Training data reconstruction: highly confidential data = "important severity"; public data = lower (L134-137, ~m27).
- **[A]** Attribute inference, membership inference ("doesn't go up to as high a severity"), property inference (L138-142, ~m27-28).
- **[A]** Model stealing (architecture or weights): "ranges from low all the way up to to critical"; open-source weights low,
  highly confidential model critical (L143-146, ~m28).
- **[A]** Input extraction (other users' inputs): reading "somebody else's uh conversations with with co-pilot" = important (L146-147, ~m29).
- **[A]** Prompt (system prompt) extraction was removed: "The system prompt is not actually seen as as a secret." (L153, ~m30).
- **[?]** L152 says "input extraction is now not in scope for any of our AI bounty programs". From context
  (he just called input extraction Important, and the paragraph is about the system prompt), he very likely means
  **prompt extraction**. Do not conclude that other-user input extraction is out of scope; check the bug bar.

### Lessons learned (the two changes since Aug 2023)

- **[A]** "prompt injection requires a security impact" (L155, ~m31). Old definition "deviate from its intended behavior"
  was judged "pretty vague" (L156-157).
- **[A]** "prompt extraction is not a vulnerability" (L159-160, ~m31-32).
- **[A]** "you shouldn't put anything confidential in your prompt" (L162, ~m32). **[D]** A secret found in a system prompt
  might be reportable as a credential leak under the classic bars; not discussed in the talk.

## 3. Examples cited (all said to be reported and fixed, L287)

- **[A]** Hidden white-on-white text on a professor's (Princeton) bio page steering Bing Chat output (L88-91, ~m17-18).
  No security impact on its own (L92).
- **[A]** Data exfiltration via indirect prompt injection from a web page: the model emits markdown rendered as an image
  whose URL points to an attacker server, carrying data from the page or "the user's preceding conversation"
  (L94-99, ~m18-19). Researcher transcribed "Johan Burger", author of "Embrace the Red" = Johann Rehberger **[?]**.
- **[A]** Same researcher: prompt injection in a received email, hidden with "non-printable characters" (L100-102, ~m19-20).
- **[A]** Copilot in the Edge sidebar summarising the visited page: page text = attacker-controllable "additional context" (L80-86, ~m16-17).
- **[?]** L288 "Rohan ... published his findings": probably the same researcher, name mistranscribed.

## 4. Submitting and report content

- **[A]** Submission entry point said as "aka.ms/secure-ai" leading to the MSRC Researcher Portal (L188, ~m37).
  **[?]** Exact short link uncertain; use the portal linked from the official bounty-ai page.
- **[A]** Form: vulnerability type, affected product, proof of concept: "a video or screenshots or written steps to reproduce" (L189-190, ~m37).
- **[A]** AI-specific additions (L193-199, ~m38-39):
  - "the exact URL or application of co-pilot uh service that you're interacting with";
  - "any choices on that you made when setting up your co-pilot service and including the text of any prompts";
  - clear evidence: screenshots, video, "or even the conversation ID";
  - how consistently it reproduces: "one one time or 10 times or 100 times";
  - "proof that the issue isn't a result of a hallucination".
- **[A]** Incomplete info: "just report the information that you have" (L238-239, ~m47); add later vectors or repro counts
  through the portal chat or the per-case email thread (L240-243, ~m47-48).
- **[A]** Questions: bounty@microsoft.com (L305, ~m60).

## 5. Research directions (speaker opinions)

- **[A]** Most potential: "the intersection between the large language model and the system that's hosting it" (L219-220, ~m43).
  Also: "I don't expect that you'll find lots of things in in in these places" (L220-221).
- **[A]** Expected trends: agents and agentic systems; multimodal models (L223-226, ~m44).
- **[A]** Defenses mentioned: Prompt Shields (deployed widely), "task tracker" (open-source injection detector) (L255-259, ~m50).
- **[A]** Practice: LLMail-Inject ("LL Mail inject" **[?]**) adaptive prompt-injection challenge (L168, ~m33);
  Bugcrowd University, HackerOne Hacker101; BlueHat recordings; arXiv ("archive" **[?]**); book
  "Not with a Bug, But with a Sticker" (transcribed "not with a bug but with a sticker attacks", L178) **[?]**;
  learn.microsoft.com to understand expected behavior and admin flags (L183-185, ~m36).
- **[A]** Content issues found by everyday users "can, uh, eventually lead to more security vulnerabilities" (L302-303, ~m59).

## 6. What the talk does NOT cover (do not attribute to it)

- **[D]** No Zero Day Quest rules beyond "public research challenge running until mid January" and the x2 AI multiplier:
  no live-event selection criteria, no invite counts, no submission windows, no multiplier table.
- **[D]** No cross-tenant / M365 Copilot / enterprise data examples; no testing rules (own accounts, rate limits).
  Those come from bounty-terms and rules of engagement (see `docs/research/15-msrc-premier-programme.md`).
- **[D]** No explicit bounty table by severity for AI.

## 7. Other transcription errors spotted

- "AI bug bot" (L105) = AI bug bar. "Morse" (L42) = MORSE. "Microsoft Black Hat celebration" (L20) probably
  "Microsoft researcher celebration at Black Hat" **[?]**. "Lin"/"Lynn" and "Adin"/"Aiden" alternate.
