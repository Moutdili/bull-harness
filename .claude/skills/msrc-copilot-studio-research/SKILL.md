---
name: msrc-copilot-studio-research
description: Load when hunting or triaging bugs in Microsoft Copilot Studio or the Power Platform around it (custom agents, topics, generative answers/actions, connectors, knowledge sources, channels, Dataverse and Dataverse plugins, PPAC, DLP, Power Pages, Power Automate, AI Builder, Dynamics 365) for an MSRC bounty submission. Also load before choosing between the AI bounty and the Dynamics 365 & Power Platform bounty for such a finding.
---

# Security research in Copilot Studio (MSRC)

Source: MSRC virtual session "Security Research in Copilot Studio" (YouTube `0Bw2YCDypUY`, 53 min),
speaker = Power Platform & Dynamics security architect. Notes with verbatim quotes:
`references/talk-notes.md`. The talk is guidance from one Microsoft engineer, **not the bounty terms**.
Official rules live on the MSRC pages; the orchestrator re-reads them before a run (the hunter has no web):
- MSRC `bounty-programs` index -> the Dynamics 365 & Power Platform bounty page (URL not checked here)
- MSRC `bounty-ai` (AI / Copilot bounty), `bounty-terms`, `pentest-rules-of-engagement`
- Repo summary of those pages: `docs/research/15-msrc-premier-programme.md`

Related skills: **`msrc-ai-bug-bounty`** owns what pays, severity and the report format (§6 there);
`ai-red-team-pyrit` owns the injection workflow and payload delivery. This skill owns the Copilot
Studio / Power Platform surface. Canary name in all three: `BH-CANARY-<id>`.

Tags: **[talk]** = said by the speaker; **[doc 15]** = official pages as summarised in doc 15;
**[PyRIT talk]** = the MSRC PyRIT webinar (see `ai-red-team-pyrit`); **[inferred]** = our deduction.

The talk date is not stated in the transcript; product names (Azure AI Studio, PVA, "dynamic chaining")
suggest 2024 [inferred]. Features and UI may have moved. Check current docs for every feature you rely on.

## 0. Harness limits that decide what is testable today

- **Websockets.** The gate refuses every websocket upgrade (`src/bh/gate/addon.py`, "websockets are not
  allowed"); `bh-browse` refuses them locally too. Copilot chat UIs probably talk over websockets
  [inferred, to be measured: PyRIT's `WebSocketCopilotTarget` defaults to a `wss://` URL]. Until the gate
  has a bounded websocket mode (to be designed, decision for Mio), a chat that only works over websockets
  is **not reachable**: record `bh-note blocked other "websocket-only chat: <url>"`. Use the HTTP
  alternative when there is one: maker-portal and PPAC REST calls, Dataverse Web API, flow and connector
  HTTP endpoints, a channel that answers over plain HTTP (Direct Line REST, if in scope; check docs).
  `bh-browse` reports refused websockets in its summary: that line is the measurement.
- **No out-of-band receiver.** `bh-oob` does not exist (issue 31 open). Prefer a proof visible without a
  receiver (§5). Otherwise `bh-note blocked oob-needed "<what and where>"`.
- **Logins.** Test accounts and their sessions go through `bh accounts` (recipes `browser`, `oauth_refresh`,
  TOTP; doc 16). Whether an interactive Entra login may be driven by the browser recipe is Mio's decision.

## 1. Architecture and attack surface

Trust boundaries [talk]. The speaker ranks only the first two by value: tenant breach = "obviously the
highest bounty award", environment breach = "something that could be bountiable". The rest follows the
slide order ("as we move down"), not a value ranking.

1. **Entra tenant**: identity plane. Cross-tenant information disclosure = top award [talk].
2. **Power Platform environment**: hosts the agent.
3. **Resource-level permissions** and **DLP policies** (connector classification, cross-tenant rules).
4. **Dataverse**: its own authorization model (security roles), distinct from Entra. Default permissions
   are a suggested hunting ground [talk].
5. Azure resources reached via private link / subnet delegation from Dataverse.
6. Customer-managed key and Lockbox: customer controls *against Microsoft*.

Components an agent is composed of (each integration point is a test seam):
- **Pro-dev extensibility: Dataverse plugins and SDK.** The only concrete success in the talk: the top
  Power Platform bounty finder, later hired, "was able to leverage, yeah, dataverse plugins to file
  several, uh, you know, critical vulnerabilities" [talk]. Same researcher was good at SSRF (§2).
- **Agent authoring**: topics, trigger phrases, nodes, entities, variables, **Power Fx** expressions on nodes
  (Power Fx runs in Dataverse or in agent nodes; where it runs changes the controls [talk]).
- **Knowledge sources**: public URL, uploaded files, SharePoint, Dataverse, Azure OpenAI on your data, custom data.
- **Generative answers** pipeline: user input -> search for relevance -> GPT grounding -> moderation/filter
  -> provenance check -> reply. Each stage is a control to probe.
- **Generative actions / dynamic chaining**: the model picks topics/connectors and fills inputs from context.
  "You can use the tracing mode to see why the model chose to do what it decided to do" [talk]: use it as
  your debugger. Where tracing mode lives in the UI ("test pane") is [inferred].
- **Conversation state store**: per-conversation memory; a place to plant data used later.
- **Connectors** (1,000+ prebuilt, custom connectors running custom code), Power Automate cloud/desktop flows (RPA).
- **AI Builder** prompts, AI plugins, Bot Framework skills, Azure Bot Service.
- **Channels**: Teams, M365, websites, Power Pages (C1 = customer, C2 = customer's customer; can be
  unauthenticated), Facebook, Azure Communication Services, Twilio, etc.
- **Authentication**: Entra ID or a custom IdP configured on the agent / Power Pages site.
- **Governance plane**: PPAC, managed environments, CoE starter kit, *disable Copilot publishing*
  ("you can go into PPAc and you turn that off" [talk]; whether it is a tenant or an environment setting is
  not said: check docs), conditional access, ALM (dev -> prod solutions).

Copilot Studio straddles M365 and Power Platform ("a child that has two homes"). Apply STRIDE at every
boundary crossing [talk], **without the D**: denial of service is forbidden by MSRC [doc 15].

## 2. Leads the speaker cited

Verdict column = the speaker's own word: **bountiable** (he says it pays), **interesting**, or **cited**
(mentioned, no verdict). None of this is the bug bar; `msrc-ai-bug-bounty` decides severity.

| Lead | Example from the talk | Speaker's verdict | Likely program (verify) |
|---|---|---|---|
| Dataverse plugins / SDK (pro-dev extensibility) | top finder's "several ... critical vulnerabilities" | cited (as past success) | Dynamics & Power Platform |
| Cross-tenant information disclosure | "use our platform to breach the tenant boundary" | bountiable ("highest bounty award") | Dynamics & Power Platform |
| Environment boundary breach | access across Power Platform environments | bountiable ("could be bountiable") | Dynamics & Power Platform |
| Publish while publishing is disabled | "would be a bounty bull find" (= bountiable) | bountiable | Dynamics & Power Platform |
| SSRF | knowledge-source URLs; "probably one of the biggest risks" for cross-tenant | interesting | Dynamics & Power Platform |
| IDOR | PPAC API: "are the attributes that ... go into the URI ... verified properly" | cited | Dynamics & Power Platform |
| DLP / governance bypass | "is there a DLP policy that you are able to bypass by using Copilot Studio" | interesting | Dynamics & Power Platform |
| Environment on my tenant abusing someone else | "that's interesting abuse" | interesting | Dynamics & Power Platform |
| Scope abuse in PPAC | environment admin seeing other environments | cited | Dynamics & Power Platform |
| Malicious insider | "identity abuse by ... being a a malicious insider" | cited | verify |
| Custom IdP as attack input | "use a custom IDP to present risk to ... the platform" | interesting | verify |
| Auth bypass on an agent | bypass the IdP configuration set on the bot | interesting (IdP vs Copilot Studio: open) | verify |
| Identity abuse via connector consent | past "zero-click fish" research, led to re-architecture; likely fixed [inferred] | cited | Dynamics & Power Platform |
| Data leak despite correct config | agent leaks internal SharePoint data after the owner secured everything | "definitely a bug" | AI or Power Platform |
| Knowledge-source poisoning | each source gives "opportunity for ... trying to poison the system" | cited | AI bounty if it crosses users |
| Stored indirect prompt injection | conversation state or Dataverse, used later ("like a blind XSS"); AI Builder prompt composed into an agent (speaker: hypothetical) | interesting | AI bounty (impact on another user) |
| Moderation bypass by language | "bypass ... different ... moderations by using different languages" | cited | AI bounty: content issue unless security impact |
| File processing abuse | "we potentially have file, uh, file abuse" | cited | verify |
| Custom connector code | "we're running custom code. So there's safety around that." | cited | verify |

Connector consent abuse: test it only between our two accounts or tenants. A consent prompt sent to
anyone else is phishing, i.e. social engineering, forbidden [doc 15].

"Finding the right home for your bug" between the AI bounty and the Dynamics & Power Platform bounty is
part of the job [talk]. State in the report why you chose that program.

## 3. Out of scope / does not pay (per the speaker; confirm on MSRC pages)

- **Maker misconfiguration**: "the goal is not for you to find an issue that a developer can create".
  "We're looking for research that will compromise the platform, right?" [talk]
- **Unauthenticated bot exposing SharePoint data** that its maker connected: "That's not necessarily a vuln"
  [talk]. Only a *bypass of the configured IdP* is interesting.
- **Global admin sees all Dataverse data**: "kind of by design" (break-glass) [talk]. Any finding obtained
  with a privileged account is suspect.
- Governance gaps that are unclear but not a boundary break: not a vuln, though feedback is welcome [talk].
- Prompt injection without impact on another user, system prompt leakage: out of scope for Copilot [doc 15].
- Full "does not pay" list: `msrc-ai-bug-bounty` §3.

## 4. Test environment setup

**Sections 4 to 6 are our method [inferred], built from the talk's hints and doc 15; the talk does not
describe a lab.** The transcript names no license or SKU: check the current Copilot Studio trial /
developer-plan docs and the "MSOBB" naming advice in the MSRC terms before buying anything. A feature
behind a licence we do not have: blocker `paid`.

1. Two tenants we own: **attacker tenant A** and **victim tenant B** (needed to prove cross-tenant impact).
   Trial tenants are encouraged by MSRC [doc 15]. Never touch a tenant we do not own.
2. In each tenant: one global admin (setup only), one **low-privilege maker**, one plain end user.
   Run every test as the low-privilege account; the admin only configures ("it's very important as you
   research to make sure that you have a low privilege user" [talk]).
3. Optional: block global-admin auto-access to the Dataverse environment, so data access is unambiguous.
4. In PPAC: separate environments (e.g. `dev`, `locked`), DLP policies (business/non-business, blocked
   connectors, cross-tenant restrictions), *disable Copilot publishing* where docs say it applies.
   Each control you set is a candidate security-feature-bypass test.
5. Test agents in our own environment: one with a public-URL knowledge source on a host we control
   (needs `bh-oob` or another receiver of ours: else blocker `oob-needed`), one with uploaded files, one
   with a SharePoint/Dataverse source holding a canary, one with a connector + flow, one published to a
   test channel with authentication on.
6. Plant `BH-CANARY-<id>` strings in victim-tenant B data. A canary appearing in A's context is the
   cleanest cross-tenant proof, and needs no receiver.
7. Harness: `scanners_allowed: false`, low request rate, own identities only [doc 15]; accounts via
   `bh accounts` (§0).

## 5. Step-by-step method [inferred unless tagged]

1. **Use the product first** [talk]: "knowing what an application assumes about you and your intent is
   incredibly powerful". Build the agent end to end, publish it, read the CoE starter kit checks: "the
   milestones for your research journey" [talk].
2. **Map controls.** For each feature, the control that should stop abuse (DLP rule, role, environment
   scope, IdP setting, moderation, publishing switch). One control = one hypothesis.
3. **Pick a boundary.** Tenant first, then environment [talk]; then DLP/role, then content filter [inferred].
4. **Watch the platform decide.** Tracing mode [talk] and the `bh-browse` HAR: which topic/action/connector
   was chosen, which API calls carry which IDs, websocket or HTTP (§0).
5. **Pro-dev first.** Dataverse plugins and SDK calls between our environments and tenants (§2, first line).
6. **IDOR.** In PPAC and maker-portal API calls, swap environment / bot / resource IDs between our two
   tenants and between environments. Our own IDs only (method: card `idor`).
7. **SSRF.** Point a knowledge source or connector URL at a host **we control**. The proof is the request
   **received on our side** (source IP, headers, redirect handling). Never point it at an internal
   address, a metadata endpoint or a Microsoft host. Internal targets stay off until Mio has read
   `pentest-rules-of-engagement` and written a decision. No receiver today: blocker `oob-needed`.
8. **Governance bypass.** Under a DLP policy or disabled publishing, try alternative paths: generative
   actions, AI plugins, Power Fx, flows, another channel. ALM solution import is our idea, not the
   speaker's: he files ALM as "not so much related to ... the Copilot Studio itself".
9. **Composition.** Content stored by one component (Dataverse row, conversation variable, AI Builder
   prompt, uploaded file) consumed by another agent or user later. Impact must cross a user or tenant
   boundary, between our own accounts. Injection workflow: `ai-red-team-pyrit` §3.
10. **Auth configuration.** Agent with Entra or custom IdP auth: can another channel, a channel endpoint or
    a Power Pages embed reach it without auth (endpoint list: current docs)? Only against our agents.
11. **Disambiguate access** before claiming [talk]: repeat with the low-privilege account, list every role
    it has, explain why it should not have reached the data.

**Proof without a receiver.** Show the effect from A's account (B's canary in A's agent answer, A's
environment listing B's object, A publishing under a disabled switch) or inside B (an action executed in B
that only A asked for). k/N repetitions as in `msrc-ai-bug-bounty` §6.

## 6. Stop rules

- **Server-side execution** (a custom connector, plugin or flow runs code we chose on Microsoft's side):
  stop at the first proof, do not explore the host. Source: the PyRIT webinar, not this talk: "reach out
  to bounty@microsoft.com if you want additional guidance on should you proceed uh or not" and "don't go
  beyond proof of concept" [PyRIT talk]. Harness gesture: `bh-note blocked other "server-side execution:
  <where>, stopped at PoC"`, then leave the lead; Mio decides whether to write to MSRC.
- **Data of a tenant or user we do not own seen by accident** [talk: "let us know immediately so we can
  contact our customers"]: stop the program at once, do not re-read, copy or summarise the data, write
  `bh-note blocked other "third-party data seen: <url or request id, no content>"`. A dedicated fact kind,
  an automatic program pause and an alert to Mio are **to build** on the harness side; until then this
  blocker is the gesture. Doc 15 forbids accessing other customers' data beyond the PoC.
- **Service agreements**: use the services in a way that "does not violate our service agreements"
  [PyRIT talk]. Throttling or a WAF challenge on a test account ends the call.
- No social engineering of Microsoft employees, partners or vendors [doc 15, PyRIT talk].

## 7. Report

Format, required fields and k/N: `msrc-ai-bug-bounty` §6. Specific to this surface:
- Microsoft vocabulary: tenant, environment, agent, topic, node, knowledge source, generative answers,
  generative actions, connector, custom connector, flow, Dataverse plugin, security role, DLP policy, PPAC,
  managed environment, channel.
- The **boundary crossed** (tenant / environment / role / DLP / IdP) and the program chosen, with one line why.
- Accounts used, their roles, why that access is not by design (admin auto-access excluded).

## 8. Pitfalls

- Testing as global admin or environment admin, then claiming access: classic *not a vuln*.
- Confusing maker misconfiguration (public unauthenticated bot) with a platform flaw.
- Prompt-injection findings with only self-impact.
- Filing under the wrong program.
- Assuming the talk's feature names are current; "each new feature is a good area to start researching"
  [talk], but re-read current docs and scope.
- Probing targets you do not own: "If it's not yours, you don't talk to it." [talk]
- Volume or automated traffic against shared Microsoft services: rate low, no scanners, no fuzzing outside
  our own Azure VMs [doc 15].
- Transcript is auto-generated (Gemini) with block cuts; quote it carefully (talk-notes caveats).
