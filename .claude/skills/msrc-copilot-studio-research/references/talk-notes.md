# Talk notes — "Security Research in Copilot Studio" (MSRC)

- Video: https://www.youtube.com/watch?v=0Bw2YCDypUY (53 min 26 s), MSRC virtual session.
- Speaker: Power Platform & Dynamics security architect (name as transcribed: "Scott Gorlik"; host
  "Alyssa Straton"; spellings unverified). Talk date not stated; product names suggest 2024.
- Source text: Gemini 2.5 Flash automatic transcript (2026-11-25), 20 raw lines. Positions below are
  given as a percentage of the transcript plus the segment (intro / talk / demo / Q&A).
- Quotes are verbatim from the transcript, including its errors. "Asserted" = what the speaker says.
  "Inferred" = our reading, not the speaker's words.

## Transcript quality caveats

- **Cut segments.** The text breaks at block boundaries at least six times; content may be lost at a cut
  (several cuts rejoin without visible loss, e.g. "unauthen" / "unauthenticated"):
  ~18 % ("when we do that," / "things."), ~32 % ("Copilot Studio and Power" / "platform"),
  ~47 % ("and I can do" / "of these things"), ~61 % ("so it can be grounded." / "that data"),
  ~76 % ("I leave it unauthen" / "unauthenticated"), ~90 % ("you can do strings." / "concatenation").
- **Likely mis-transcriptions:** "Power Effects" = Power Fx; "PPC"/"P-PAC" = PPAC; "OATH" = OAuth;
  "bought framework" = Bot Framework; "EVA bots" probably PVA (Power Virtual Agents) bots;
  "intra tenant" = Entra tenant; "SAS" = SaaS; "voln" = vuln.
- **"research done by Samsung last year"** on connector consent / zero-click phishing (~86 %): the
  company name is doubtful. Do not cite it in a report without finding the original research.
- **"Eric"**, the hired top bounty finder (~20 %, ~82 %): name unverified. What he did is not in doubt
  (see "Pro-dev extensibility" below).
- The slides were not transcribed ("Link Soup" of resources promised on LinkedIn, not available here).

## Points from the talk

### Goal and highest-value bug (intro, ~3 %)
- Asserted: "your biggest goal is to find cross-tenant information disclosure" ... "that's going to be,
  you know, obviously the highest bounty award."
- Asserted: environment is the next trust boundary: "any breach of that boundary, again, that's going to
  be, you know, something that could be bountiable."
- Asserted (Q&A, ~80 %): "our highest bountiable award in the Dynamics and Power Platform, uh, bounty
  program is the cross-tenant information disclosure."

### Pro-dev extensibility: Dataverse plugins and SDK (~20 %)
- Asserted: "as we go from the low code and and no code systems, we can build into prodev extensibility. So
  in, in this area, um, this is where a lot of very interesting SDK interactions can occur".
- Asserted: the hired top bounty finder "was able to leverage, yeah, dataverse plugins to file several, uh,
  you know, critical vulnerabilities". The only concrete success story of the talk.
- Asserted (Q&A, ~82 %): on SSRF, "That's what Eric was very good at finding."

### Dataverse authorization (~7 %)
- Asserted: Dataverse "authorization model, which is distinct from Entra" ... "there might be some
  interesting vulnerabilities based on some default permissions."

### Platform vs maker misconfiguration (~12 %)
- Asserted: "the goal is not for you to find an issue that a developer can create" ... "a loss of
  governance of data for an enterprise."
- Asserted: "We're looking for research that will compromise the platform, right?"
- Asserted: governance-feature insight is still "very important to us".

### Attack surface list (~14 %)
- Asserted: "topics, Gen AI, channel publishing, analytics. Each one of these areas is a is a spot where
  you can introduce some potential risk".
- Asserted: channel publishing risks, AI plugins and "indirect prompt injection", generative actions that
  may "lose its context and and some of the grounding controls".
- Asserted: PPAC is the place to configure environments, connectors and DLP for testing.

### Principle of least surprise (~17 %)
- Asserted: "how have we made things so simple that it potentially hides some risk, uh, or, you know,
  leak of credential or or identity".

### Tracing mode as debugger (~22 %, demo ~28 %)
- Asserted: "When you start working with a SAS, uh, it, it can be difficult to understand what decisions
  the platform is making and why".
- Demo: "You can use the tracing mode to see why the model chose to do what it decided to do."
- Demo shows dynamic chaining: a Power Automate flow fills user-profile variables at conversation start;
  the model passes values between connectors (ServiceNow ticket, weather API).

### Connectors and composition (~34-41 %)
- Asserted: "1,200 plus pre-built connectors" (earlier, ~14 %: "a thousand plus connectors").
- Asserted: "it's not just testing the Copilot Studio, it's testing how it fits into the larger power
  platform ecosystem."
- Asserted: example report shape: "I didn't find a bug in AI Builder, but when I take that AI Builder
  prompt" into an agent "I can end up with indirect prompt injection" (speaker calls it hypothetical).

### Identity (~43 %)
- Asserted: "abuse of Entra is interesting. Abusing, like using your own custom IDP, that's also
  interesting."

### Cross-tenant and DLP bypass (~49 %)
- Asserted: "can I create an environment on my tenant and have that abuse somebody else? Um, that's
  interesting abuse."
- Asserted: breaching a DLP policy or governance control "That's an interesting security feature bypass."

### Two bounties (~51 %)
- Asserted: "We have the AI bounty and we have the Dynamics and Power Platform bounty." ... "Finding the
  right home for your bug is going to be a very interesting challenge".
- Inferred: the report should argue which program fits; the speaker does not give a decision rule.

### Conversation state store / stored injection (~53 %)
- Asserted: "can I put something into a conversation state or into a data verse that I can then leverage
  later, kind of like a blind XSS".

### Data leak despite secure config (~55 %)
- Asserted: "I've done everything that I can do to secure my co-pilot, and it's still leaking my SharePoint
  data inappropriately. That's definitely a bug" (context: internal SharePoint as knowledge source).

### Generative building (~57 %)
- Asserted: the system returns "the YAML structure of the the agent flow", which can be refined.
- Inferred: the agent definition is YAML; a possible place to look at what the maker UI hides. Unverified.

### SSRF and file processing on knowledge sources (~62 %)
- Asserted: "we have SSRFs, you know, for when I'm reaching out and talking to those URLs, or we
  potentially have file, uh, file abuse".

### Moderation bypass by language (~63 %)
- Asserted: "where can I bypass, uh, different, uh, moderations by using different languages, right?"
- Inferred: check the AI bounty scope before filing a pure content-filter bypass; doc 15 lists
  limits on prompt-injection findings.

### CoE starter kit as research map (~68 %)
- Asserted: "what are the things that the starter kit is considering?" ... "a good opportunity to get
  basically the milestones for your research journey."

### Disabled publishing (~69 %)
- Asserted: "if I can disable publishing, yet still publish, is that a security feature bypass? That's,
  that would be a bounty bull find." ("bounty bull" = bountiable, transcription error.)

### Global admin and low-privilege accounts (~70-72 %)
- Asserted: "global admins are added to each Dataverse environment so that they can break glass"; a
  configuration can block this.
- Asserted: "If you are the global admin of that tenant and you're able to see all Dataverse data,
  that's kind of by design".
- Asserted: "it's very important as you research to make sure that you have a low privilege user".
- Asserted: "you need to disambiguate your access, um, figure out how you had access to the data".

### DLP is the core enterprise control (~75 %)
- Asserted: "data loss prevention policies, uh, this is the core of how an enterprise can secure itself."
- Asserted: "is there a DLP policy that you are able to bypass by using Copilot Studio".

### Unauthenticated bot is not a vuln (~76 %)
- Asserted: unauthenticated bot giving SharePoint data to anonymous users: "That's not necessarily a vuln.
  It's just not a great system that I've built."
- Asserted: "if you have the ability to bypass the IDP configuration that you've set up for your bot,
  that would be an interesting vuln."
- Asserted: IdP vuln vs Copilot Studio vuln is an open question "we can discuss".

### New features (~78 %)
- Asserted: "each new feature is a good area to start researching."

### Rules of engagement and incidental data (Q&A, ~81 %)
- Asserted: "know your targets and stay within the bounty, uh, rules of engagement. If it's not yours,
  you don't talk to it."
- Asserted: incidental leakage "that's fair game. And just let us know immediately so we can contact our
  customers".
- Inferred: "fair game" means reportable, not permission to explore further; MSRC terms (doc 15) forbid
  accessing other customers' data beyond the PoC. Follow the terms, not this phrase.

### SSRF and IDOR as cross-tenant paths (Q&A, ~82 %)
- Asserted: "I think SSRF is, is probably one of the biggest risks."
- Asserted: PPAC API endpoints: "are the attributes that, that go into the URI, are they all verified
  properly, or do we have an IDOR vuln?"

### STRIDE at every boundary (Q&A, ~85 %)
- Asserted: apply STRIDE ("spoofing, tampering, repudiation, information disclosure, denial of service and
  escalation of privileges") "at each one of those boundary crossing conditions"; Copilot Studio is "kind of
  like a a child that has two homes" (M365 and Power Platform).

### Connectors: consent abuse and identity (Q&A, ~86-88 %)
- Asserted: past research on "how the application consent process works and how it can be abused for a
  zero-click fish" led Microsoft to re-architect the connectors ecosystem.
- Asserted: "with the custom connectors, you know, we're running custom code. So there's safety around that."
- Asserted: OWASP low-code/no-code top 10: "the first item is identity abuse" and "connectors are that area".
- Inferred: the original consent-abuse class is likely fixed; new variants need fresh evidence.

### Power Fx runs in several places (Q&A, ~89-91 %)
- Asserted: "Power FX is a language that doesn't really care where it runs per se, but where it runs
  affects what are the security controls".
- Asserted: runs in Dataverse or in the agent nodes.

### PPAC scope abuse (Q&A, ~93 %)
- Asserted: environment admin should only see their environment: "can I can I see things I'm not supposed
  to see through PPC?"

### How to start (Q&A, ~96-97 %)
- Asserted (relayed from bounty team): start with the bounty page, scope, rules of engagement, getting-started material.
- Asserted: "the best way to learn how to do security research over any application is to use the application."
- Asserted: "knowing what an application assumes about you and your intent is incredibly powerful".
- Contact given: bounty@microsoft.com (questions), speaker via LinkedIn.

## Not in the talk (do not attribute to the speaker)
- Licenses, SKUs, trial procedures, tenant creation steps.
- Payout amounts for Copilot Studio findings.
- Exact URLs of bounty pages and the deck's "Link Soup".
- Lab setup (two tenants, canaries, ALM import as a bypass path, HAR): our construction. The speaker even
  files ALM as "not so much related to, uh, the Copilot Studio itself".
- Stop rule on server-side execution: from the PyRIT webinar, not this talk.

## Inferred, flagged in SKILL.md
- STRIDE is applied **without the D** in the harness: DoS is forbidden by MSRC (doc 15).
- Where tracing mode sits in the UI ("test pane"): not said.
- Whether *disable Copilot publishing* is a tenant or environment setting: not said ("you can go into PPAc
  and you turn that off").
