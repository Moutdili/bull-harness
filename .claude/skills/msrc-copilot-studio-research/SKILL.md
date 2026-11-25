---
name: msrc-copilot-studio-research
description: Load when hunting or triaging bugs in Microsoft Copilot Studio or the Power Platform around it (custom agents, topics, generative answers/actions, connectors, knowledge sources, channels, Dataverse, PPAC, DLP) for an MSRC bounty submission. Also load before writing an MSRC report on a Copilot Studio finding, to pick the right bounty program and avoid *not a vuln* outcomes.
---

# Security research in Copilot Studio (MSRC)

Source: MSRC virtual session "Security Research in Copilot Studio" (YouTube `0Bw2YCDypUY`, 53 min),
speaker = Power Platform & Dynamics security architect. Notes with verbatim quotes:
`references/talk-notes.md`. The talk is guidance from one Microsoft engineer, **not the bounty terms**.
Official rules live on the MSRC pages; verify there before acting:
- MSRC `bounty-programs` index -> the Dynamics 365 & Power Platform bounty page (URL not checked here)
- MSRC `bounty-ai` (AI / Copilot bounty), `bounty-terms`, `pentest-rules-of-engagement`
- Repo summary of those pages: `docs/research/15-msrc-premier-programme.md`

The talk date is not stated in the transcript; product names (Azure AI Studio, PVA, "dynamic chaining")
suggest 2024. Features and UI may have moved. Check current docs for every feature you rely on.

## 1. Architecture and attack surface

Trust boundaries, from most to least valuable (speaker's ordering):

1. **Entra tenant** — identity plane. Breaking it = cross-tenant information disclosure = top award.
2. **Power Platform environment** — hosts the agent. Breaking environment isolation is bountiable.
3. **Resource-level permissions** and **DLP policies** (connector classification, cross-tenant rules).
4. **Dataverse** — its own authorization model (security roles), distinct from Entra. Default
   permissions are a suggested hunting ground.
5. Azure resources reached via private link / subnet delegation from Dataverse.
6. Customer-managed key and Lockbox — customer controls *against Microsoft*.

Components an agent is composed of (each integration point is a test seam):
- **Agent authoring**: topics, trigger phrases, nodes, entities, variables, **Power Fx** expressions on nodes.
- **Knowledge sources**: public URL, uploaded files, SharePoint, Dataverse, Azure OpenAI on your data, custom data.
- **Generative answers** pipeline: user input -> search for relevance -> GPT grounding -> moderation/filter
  -> provenance check -> reply. Each stage is a control to probe.
- **Generative actions / dynamic chaining**: the model picks topics/connectors and fills inputs from context.
  Tracing mode (test pane) shows why the model chose an action: use it as your debugger.
- **Conversation state store**: per-conversation memory; a place to plant data used later.
- **Connectors** (1,000+ prebuilt, custom connectors running custom code), Power Automate cloud/desktop flows (RPA).
- **AI Builder** prompts, AI plugins, classic Dataverse plugins, Bot Framework skills, Azure Bot Service.
- **Channels**: Teams, M365, websites, Power Pages (C1 = customer, C2 = customer's customer; can be
  unauthenticated), Facebook, Azure Communication Services, Twilio, etc.
- **Authentication**: Entra ID or a custom IdP configured on the agent / Power Pages site.
- **Governance plane**: Power Platform Admin Center (PPAC), managed environments, CoE starter kit,
  *disable Copilot publishing* tenant switch, conditional access, ALM (dev -> prod solutions).

Copilot Studio straddles M365 and Power Platform ("a child that has two homes"). Apply STRIDE at every
boundary crossing (M365 <-> Copilot Studio <-> Power Platform <-> Azure AI).

## 2. Vulnerability classes the speaker called valid

| Class | Example from the talk | Likely program (verify) |
|---|---|---|
| Cross-tenant information disclosure | "use our platform to breach the tenant boundary"; an environment in my tenant abusing someone else | Dynamics & Power Platform (highest) |
| Environment boundary breach | access across Power Platform environments | Dynamics & Power Platform |
| SSRF | knowledge-source URLs fetched by the platform; named the biggest cross-tenant risk | Dynamics & Power Platform |
| IDOR | PPAC / platform API endpoints: are URI attributes verified? | Dynamics & Power Platform |
| Security feature bypass | bypass a DLP policy via Copilot Studio; publish while publishing is disabled in PPAC | Dynamics & Power Platform |
| Scope abuse in PPAC | environment admin seeing other environments / tenant-level data | Dynamics & Power Platform |
| Auth bypass on an agent | bypass the IdP configuration set on the bot | discussed as open: IdP vs Copilot Studio |
| Identity abuse via connectors | consent flow abused for zero-click phishing (past third-party research, led to connector re-architecture) | Dynamics & Power Platform |
| Data leak despite correct config | agent leaks internal SharePoint data after the owner secured everything | AI or Power Platform |
| Indirect prompt injection with cross-boundary impact | plant data in conversation state or Dataverse, triggered later ("like a blind XSS"); AI Builder prompt composed into an agent | AI bounty (must show impact on another user) |
| Moderation bypass | using other languages to bypass moderation | AI bounty (check if in scope) |
| File processing abuse | how uploaded knowledge files are processed | verify |
| Custom connector code isolation | custom connectors run custom code | verify |

The speaker's framing: "Finding the right home for your bug" between the AI bounty and the Dynamics &
Power Platform bounty is part of the job. State in the report why you chose that program.

## 3. Out of scope / does not pay (per the speaker; confirm on MSRC pages)

- **Maker misconfiguration**: a developer building an agent that loses governance of data is not the
  target. "We're looking for research that will compromise the platform"
- **Unauthenticated bot exposing SharePoint data** that its maker connected: "not necessarily a vuln",
  like publishing an unauthenticated web app. Only a *bypass of the configured IdP* is interesting.
- **Global admin sees all Dataverse data**: by design (break-glass; admins are added to each Dataverse
  environment unless that is blocked). Any finding obtained with a privileged account is suspect.
- Governance gaps that are unclear but not a boundary break: *not a vuln*, though feedback is welcome.
- From repo doc 15 (official bounty-ai page): prompt injection without impact on another user and system
  prompt leakage are out of scope for Copilot.

## 4. Test environment setup

The transcript does not name licenses or SKUs. Do not assume them: check the current Copilot Studio
trial / developer-plan docs and the "MSOBB" naming advice in the MSRC terms before buying anything.

1. Two tenants we own: **attacker tenant** and **victim tenant** (needed to prove cross-tenant impact).
   Trial tenants are encouraged by MSRC. Never touch a tenant we do not own.
2. In each tenant, at least: one global admin (setup only), one **low-privilege maker**, one plain end user.
   Run every test as the low-privilege account; the admin only configures.
3. Optional: block global-admin auto-access to the Dataverse environment, so data access is unambiguous.
4. In PPAC: create separate environments (e.g. `dev`, `locked`), set DLP policies (business/non-business,
   blocked connectors, cross-tenant restrictions), toggle *disable Copilot publishing* on `locked`.
   Each control you set is a candidate security-feature-bypass test.
5. Build test agents in your own environment: one with a public-URL knowledge source pointing to a
   server **we control**, one with uploaded files, one with a SharePoint/Dataverse source holding a
   canary string, one with a connector + Power Automate flow, one published to a test channel with
   authentication on.
6. Plant unique canary strings (e.g. `MSOBB-CANARY-<random>`) in victim-tenant data. A canary appearing
   in the attacker context is the cleanest cross-tenant proof.
7. Harness: `scanners_allowed: false`, low request rate, own identities only (see doc 15). Interactive
   Entra login + MFA: the operator provides tokens; do not automate credential entry against Microsoft.

## 5. Step-by-step method

1. **Use the product first.** The speaker's top advice: learn what the app assumes about you and your
   intent. Build the agent end to end, publish it, read the CoE starter kit checks for Copilot Studio:
   they list what the platform considers risky, i.e. research milestones.
2. **Map controls.** For each feature, write the control that should stop abuse (DLP rule, role,
   environment scope, IdP setting, moderation, publishing switch). One control = one hypothesis.
3. **Pick a boundary.** Prefer, in order: tenant > environment > DLP/role > content filter.
4. **Watch the platform decide.** Use the test pane tracing mode and the browser network log to see
   which topic/action/connector was chosen and which API calls carry which IDs.
5. **Test identifiers (IDOR).** In PPAC and maker-portal API calls, swap environment / bot / resource IDs
   between our two tenants and between environments. Our own IDs only.
6. **Test outbound fetches (SSRF).** Point knowledge sources or connector URLs at our own listener;
   record source IP, headers, redirect handling. If the platform follows redirects or reaches
   non-public addresses, stop at the first proof and report; do not explore Microsoft internals.
7. **Test governance bypass.** Under a DLP policy or disabled publishing, try alternative paths:
   generative actions, AI plugins, Power Fx, flows, ALM import of a solution, another channel.
8. **Test composition.** Content stored by one component (Dataverse row, conversation variable, AI
   Builder prompt, uploaded file) consumed by another agent or user later. Impact must cross a user or
   tenant boundary, between our own accounts.
9. **Test auth configuration.** Agent with Entra or custom IdP auth: can another channel, a channel
   endpoint or a Power Pages embed reach it without auth (endpoint list: current docs, not the talk)? Only against our agents.
10. **Disambiguate access** before claiming: repeat with the low-privilege account, list every role it
    has, and explain why it should not have reached the data.

## 6. Proof and report

The speaker values reports written in the platform's vocabulary that let engineering fix fast.
- Use Microsoft terms: tenant, environment, agent, topic, node, knowledge source, generative answers,
  generative actions, connector, custom connector, flow, Dataverse security role, DLP policy, PPAC,
  managed environment, channel.
- State the **boundary crossed** (tenant / environment / role / DLP / IdP) and the program chosen, with
  a one-line reason.
- List the accounts used, their roles, and why that access is not by design (admin auto-access excluded).
- Minimal reproducible steps from a clean environment, exact requests (redacted tokens), product
  version/region/date, canary proof, screenshots or HAR excerpt.
- Impact in concrete terms: whose data, which tenant, what an attacker needs (privileges, user interaction).
- If data from a tenant we do not own appears incidentally: stop, do not access more, report to MSRC
  immediately (speaker: "let us know immediately so we can contact our customers").
- Human review of every report before submission (MSRC AI-generated report rule, doc 15).

## 7. Pitfalls

- Testing as global admin or environment admin, then claiming access: classic *not a vuln*.
- Confusing maker misconfiguration (public unauthenticated bot) with a platform flaw.
- Prompt-injection findings with only self-impact: out of scope for AI bounty.
- Filing under the wrong program; say why the bug belongs where you file it.
- Assuming the talk's feature names are current; Copilot Studio ships fast. The speaker suggests each
  new feature (Copilot Studio blog) is a good research start, but re-read current docs and scope.
- Probing targets you do not own: "If it's not yours, you don't talk to it."
- Volume or automated traffic against shared Microsoft services: keep rate low, no scanners, no fuzzing
  outside our own Azure VMs.
- Transcript is auto-generated (Gemini) with cut segments; quote it carefully (see talk-notes caveats).
