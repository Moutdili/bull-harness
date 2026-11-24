# 03 — Inventaire des dépôts et outils

Tous les chiffres marqués ✅ ont été lus via l'API GitHub le **2026-11-22** (étoiles, langage, dernier push, licence, archivé).

---

## A. Frameworks offensifs agentiques

| Dépôt | ★ | Langage | Dernier push | Licence | Note |
|---|---|---|---|---|---|
| `vxcontrol/pentagi` | 34 809 | Go | 2026-11-13 | MIT | Stack compose, sandbox Docker, pgvector, reflector. CVE-2026-14784 corrigée en v2.2 |
| `BaaRai/ARTEX` | 16 163 | Go | 2026-11-22 | AGPL-3.0 | ⚠ Retiré en oct. 2026 selon Elastic ; répond à l'API aujourd'hui — rétabli ou réplique, à vérifier |
| `0x4m4/hexstrike-ai` | 13 822 | Python | 2026-08-03 | MIT | Serveur MCP, ~150 outils, **packagé Kali v6.0** |
| `AIPentest/CyberStrikeAI` | 8 929 | Go | 2026-11-19 | Apache-2.0 | Console complète : C2, WebShell, bridges chat. Créé 2025-11-08 |
| `oritera/Cairn` | 5 686 | Python | 2026-09-07 | AGPL-3.0 | Blackboard fact/intent, workers CLI, arXiv 2609.32700 |

## B. Projets adjacents (même catégorie, cités par Elastic Security Labs)

| Dépôt | ★ | Langage | Dernier push | Licence | Rôle |
|---|---|---|---|---|---|
| `usestrix/strix` | 77 078 | Python | 2026-11-22 | Apache-2.0 | Découverte de vulnérabilités ; utilisé dans la campagne Gambit pour le *finding* |
| `KeygraphHQ/shannon` | 52 188 | TypeScript | 2026-11-20 | AGPL-3.0 | Pentest white-box |
| `GreyDGL/PentestGPT` | 16 554 | Python | 2026-07-14 | MIT | Le doyen (2023), approche guidée par LLM |
| `aliasrobotics/CAI` | 9 872 | Python | 2026-08-22 | NOASSERTION | **Archivé** |
| `CyberStrikeus/cyberstrike` | 3 680 | TypeScript | 2026-11-22 | AGPL-3.0 | ⚠ **Homonyme — ce n'est PAS CyberStrikeAI** |
| `samugit83/redamon` | 3 469 | Python | 2026-11-19 | MIT | Recon + exploitation |
| `GH05TCREW/pentestagent` | 3 328 | Python | 2026-11-09 | MIT | Agent de pentest |
| `IPA-Lab/HackingBuddyGPT` | 1 340 | Python | 2026-10-24 | MIT | Recherche académique, privesc Linux |
| `BerylliumSec/nebula` | 1 163 | Python | 2026-11-22 | BSD-2-Clause | Agent autonome |
| `BugTraceAI/BugTraceAI` | 370 | Shell | 2026-10-19 | Apache-2.0 | Scanner assisté |

À ajouter à la veille : **Xalgorix** (vérificateur qui ré-exploite chaque finding) — déjà noté dans `00-veille.md` R2.

## C. MCP

| Dépôt | ★ | Note |
|---|---|---|
| `mwnickerson/bloodhound_mcp` | 146 | ✅ Python, GPL-3.0, push 2026-08-19. Expose l'API REST de BloodHound CE à Claude Desktop. Signature réseau : token Bearer + cadence élevée sur `/api/v2/...` |

## D. Détection et contenu défensif

| Ressource | Usage |
|---|---|
| `elastic/detection-rules` ✅ 2 992 ★, push 2026-11-20 | Règles Elastic publiques — référence de format et de qualité |
| `elastic/protections-artifacts` | Artefacts YARA/protections |
| **Sigma HQ** + `sigma-cli` | Format portable ; `sigma convert -t splunk` / `-t sentinel` pour les traductions |
| **Sysmon for Linux** | Schéma de champs aligné sur le ruleset Sigma `linux` — fait gagner une étape de mapping |
| **Wazuh** | SIEM open source léger : manager + indexer + dashboard + agents |
| **Zeek** | Logs conn/http/dns/tls au format TSV/JSON, très utilisé par les règles réseau |
| **mitmproxy** | Corps de requêtes, en-têtes, User-Agents, timing — ce que nginx ne logue pas |

## E. Scopes bug bounty (déjà dans `00-veille.md`)

- `arkadiyt/bounty-targets-data` — dumps horaires des scopes H1/Bugcrowd/Intigriti/YWH.
- `sw33tlie/bbscope` — extraction multi-plateformes.

## F. Veille et contenu

### `Ignitetechnologies` — « Hacking Articles » ✅

- Compte créé 2016-10-30, New Delhi, **6 008 followers**, **34 repos publics**, site hackingarticles.in.
- Top repos : `Mindmap` **9 569 ★**, `Privilege-Escalation` 3 653, `BurpSuite-For-Pentester` 2 639, `HackTheBox-CTF-Writeups` 1 846, `Vulnhub-CTF-Writeups` 1 268, `Linux-Privilege-Escalation` 1 006.
- **Verdict : agrégation, pas recherche.** Cheatsheets et mindmaps utiles pour débutants OSCP/CTF. Plusieurs repos morts (Command-Control 2020, fork PayloadsAllTheThings 2021, bugbounty 2022). **Zéro dépôt de détection.**
- **`AI-Pentest`** : créé **et** poussé le 2026-07-21, **9 Ko**, 2 fichiers (README + un blob), **aucune licence**, **aucun code**, 56 ★. Six liens vers leurs propres articles + formulaire Google vers leur formation payante. **Entonnoir marketing.**
- **Ce qu'on garde** : l'article du 21 juin 2026 *« AI-Powered Active Directory Pentesting with Claude, HexStrike AI & NetExec »* — chaîne AD complète et relecture des event logs côté défenseur (section DCSync / Event 4662). Et l'article BloodHound MCP du 19 juin 2026.
- **Hygiène à ne pas reproduire** : leur labo tourne en `192.168.1.x`, non isolé.

### Autres

- `rtk-ai/rtk` — Rust Token Killer, déjà noté en R1 de la veille.

---

## G. Sources primaires utilisées pour la recherche

| Organisation | Apport |
|---|---|
| **Unit 42** (Palo Alto) | CL-STA-1238, 25 opérations / 19 orgs, usage de Cairn |
| **AWS Threat Intelligence** | Instance Cairn exposée, 0-day, 11 minutes |
| **Elastic Security Labs** | Comparatif des 5 frameworks, télémétrie, tempo |
| **Google GTIG / Mandiant** | ARTEX, HexStrike, Cairn en réponse à incident |
| **NorForge** | Panels Cairn exposés, ~10 % de succès, ~23 h |
| **Gambit Security** | Campagne retail, 600k cartes, ~25 $/cible |
| **Team Cymru** (Will Thomas) | CyberStrikeAI ↔ campagne FortiGate |
| **Odin / Brandefense** | 340 endpoints PentAGI, 22 confirmés |
| **arXiv 2609.32700** | Architecture et mesures de Cairn |

À rejouer avant toute publication : ces chiffres datent de sept.–nov. 2026 et bougent vite.
