# 02 — Frameworks offensifs agentiques

Cinq projets partagent la même boucle : un LLM planifie, des outils exécutent, les résultats alimentent l'étape suivante. **Aucun n'applique l'autorisation dans le code**, et plusieurs désactivent les demandes d'approbation par défaut.

Chiffres d'étoiles vérifiés par API GitHub le 2026-11-22.

---

## ARTEX — `BaaRai/ARTEX`

- **Nature.** Planner événementiel + workers parallèles. L'humain est réduit à un agent de chat qui observe et oriente par des *hints*.
- **Spécificité.** Une extension navigateur embarquée enregistre la session authentifiée de l'opérateur (captchas et codes à usage unique résolus une fois) et la rejoue comme preuve pour les agents.
- **Défauts.** Garde-fou sur les commandes destructrices (`rm -rf`, `mkfs`), allowlist d'actifs vide par défaut. Le mécanisme de *rules of engagement* a été retiré ; les actifs découverts sont ajoutés au scope automatiquement.
- **Réel.** Google GTIG et Mandiant l'ont observé en réponse à incident. Microsoft attribue son usage à **Storm-0940** (compromission de la chaîne d'approvisionnement ConnectWise). Rafales de **2 à 25 secondes**.
- **Disponibilité.** Elastic rapporte que le dépôt original a été retiré en octobre 2026 et que des forks ont pris le relais. **⚠ Au 22 nov. 2026, l'API GitHub répond sur `BaaRai/ARTEX` (16 163 ★, AGPL-3.0, push daté du 22 nov. 2026)** — soit rétabli, soit réplique. À vérifier avant de citer.

## Cairn — `oritera/Cairn`

- **Nature.** Moteur de résolution de problème générique, pas un outil de pentest. Blackboard avec graphe **fait / intention / hint**.
- **Boucle.** `Bootstrap` → `Reason` → `Explore`, répétée jusqu'à ce que le modèle juge l'objectif atteint ou les options épuisées. Workers sans rôles fixes, coordination par stigmergie (le tableau partagé), pas de communication directe.
- **Workers.** CLI d'agents de code existants — **Claude Code, Codex, Pi** — dans des conteneurs Kali. Model-agnostic.
- **Papier.** arXiv 2609.32700. Sur les tâches à fort effort (≥ 1 M tokens), solution plus rapide dans 76,5 % des cas, jusqu'à 3,08× ; surcoût de tokens notable sur les tâches faciles.
- **Réel.** **CL-STA-1238** (Unit 42) : 25 opérations, 19 organisations, accès confirmé chez 10. Modèles : Zhipu GLM 5.2 (13 ops), DeepSeek V4 Flash (8), V4 Pro (4). Fork custom hébergé à Hong Kong (`154.44.31.4`), nœud de sortie aux US (`82.29.129.54`). Pack de skills « AIScan Runner Skills » absent de l'amont.
- **0-day.** AWS : instance Cairn exposée sans auth, agents partis d'une application d'imagerie médicale, path traversal sur un paramètre de nom de fichier, écriture arbitraire en **~11 minutes**, puis reverse shell root via `sitecustomize.py`. Aucun avis de sécurité n'existait à la découverte.
- **Échec documenté.** 148 actions sur ~16 h contre un Redis durci, zéro succès. Un run de 6 h contre un serveur GPU : ~80 usernames collectés, 30 000 combinaisons testées, zéro login.
- **Taux.** NorForge, sur des panels exposés : **~10 % de réussite**, ~23 h en moyenne start→goal sur les runs réussis, ~140 faits par projet.
- **Garde-fou.** Les prompts par défaut interdisent au modèle de refuser. Si un worker refuse quand même, le dispatcher le met de côté 5 secondes et confie la tâche à un autre.

## CyberStrikeAI — `AIPentest/CyberStrikeAI`

- **Nature.** Console d'opérateur complète, pas un planificateur. Go, Apache-2.0, créé le 2025-11-08, **8 929 ★**, 151 releases.
- **Orchestration.** Eino (ByteDance) : single-agent, Deep, Plan-Execute, Supervisor. Workflows graphiques, rôles, 100+ recettes d'outils en YAML, MCP (HTTP/stdio/SSE), RAG, skills.
- **Ce qui le distingue.** C'est le seul des cinq qui est une **plateforme d'intrusion de bout en bout** : **C2 intégré** (listeners, beacons chiffrés, sessions, task queue, payload helpers), **WebShell manager** (terminal virtuel, opérations fichiers), bridges Telegram / Slack / Discord / DingTalk / WeCom / QQ, gestion d'actifs et de chaînes d'attaque avec replay.
- **Défauts.** Mode approbation **désactivé** par défaut. Blocklist de domaines gouvernementaux uniquement. Les skills embarquées couvrent contournement de rate-limit, bascule proxy/Tor et anti-forensics.
- **Réel.** Team Cymru (Will Thomas) a corrélé une instance sur `212.11.64.250` — la même IP que la campagne **500+ FortiGate en 5 semaines** (bypass SSO FortiCloud, CVE-2026-24858). Elastic a tracé une intrusion AWS jusqu'à un serveur CyberStrikeAI : **8 identités AWS**.
- **Télémétrie.** Implant qui *check-in* toutes les 5 secondes sans jitter. C'est un signal de cadence très propre.

## PentAGI — `vxcontrol/pentagi`

- **Nature.** Plateforme self-hosted autonome. Go, MIT + EULA d'usage acceptable, **34 809 ★**, v2.2.0 du 5 oct. 2026.
- **Architecture.** Console web + REST/GraphQL, sandbox Docker isolée par flow, 20+ outils Kali, mémoire **PostgreSQL + pgvector**, knowledge graph Neo4j/Graphiti optionnel, observabilité Langfuse/Grafana/OTel/Jaeger/Loki.
- **Agents.** primary, assistant, generator, refiner, adviser, **reflector** (relance un agent qui cesse d'appeler des outils, en répondant à sa place dans la voix de l'utilisateur), searcher, enricher, coder, installer, pentester, memorist, reporter.
- **Défauts.** `ASK_USER=false` dans le compose. Neuf prompts de rôle s'ouvrent sur un bloc de pré-autorisation.
- **CVE.** **CVE-2026-14784** — prise de contrôle de l'hôte via la sandbox, corrigée en 2.2.
- **Réel.** Odin/Brandefense : **340 endpoints PentAGI** exposés sur Internet, **22 confirmés**. Un des contrôleurs partageait le serveur avec un port ARTEX et un dropzone d'upload-bypass.

## HexStrike — `0x4m4/hexstrike-ai`

- **Nature.** Ce n'est **pas** un agent : un serveur MCP exposant ~150 fonctions d'outils offensifs à l'assistant que l'opérateur utilise déjà. Aucun modèle propre, aucune boucle de planification. Python, MIT, **13 822 ★**.
- **Packaging.** ✅ **Présent dans les dépôts Kali** : `sudo apt install hexstrike-ai`, v6.0, 2,76 Mo installés, dépendances mitmproxy / python3-mcp / pwntools / selenium. Serveur sur `127.0.0.1:8888`, pool de workers.
- **Pourquoi c'est important.** C'est le framework le plus complet à installer en une commande. La barrière n'est plus technique.

---

## Pourquoi les affiliates ransomware ne basculent pas

1. **Mauvais étage de la kill chain.** Ces outils font de l'initial access (web, edge, cloud). Le métier d'affiliate est 100 % post-exploit : CS/Sliver/Brute Ratel, RMM, évasion EDR, vol de credentials, encryptor ESXi. Aucun des cinq ne fait ça.
2. **Bruit.** Scanners stock, pas de jitter, rafales de secondes, panels exposés sans authentification — donc observés par les vendors avant les victimes.
3. **ROI.** ~10 % de réussite sur Cairn, ~23 h pour y arriver, coût tokens + infra + tuning contre un toolchain déjà amorti.
4. **Dépendance.** Le provider LLM journalise ; le modèle peut refuser ; le dépôt peut disparaître (ARTEX, oct. 2026).
5. **Le goulot n'est pas là.** Un affiliate achète un accès à un IAB. Il n'a aucun intérêt à rebuild sa chaîne pour gagner du temps sur la partie qui n'est pas son problème.
6. **Skillset.** Monter Compose + PostgreSQL + pgvector + Neo4j est un filtre à lui seul.

**Ce qui ferait basculer** : couverture post-exploit complète ; harness custom non publié ; modèle AIaaS/IAB (vendre l'accès, pas l'outil) ; coût d'un run sous le prix d'un accès acheté.

---

## Angle détection — ce que les défenseurs voient vraiment

- **Le comportement, pas l'empreinte.** Accès aux credentials, exécution distante, outils offensifs lancés par un compte de service, énumération d'API cloud. Les chaînes et les défauts changent à chaque release ; les actions non.
- **Tempo par identité** : nombre d'actions sensibles distinctes par identité et par rôle émetteur dans une fenêtre courte.
- **Séquence inter-sessions** : découverte → accès aux secrets → exécution distante, jointes sous un même rôle.
- **Après un blocage**, attendre un changement de route : proxies, User-Agents, en-têtes de forwarding, proxies gratuits du pays de la cible, puis Tor. Les détections ancrées sur l'adresse source vieillissent mal ; celles ancrées sur **ce qui est demandé** tiennent.
- **La révocation ne stoppe pas un agent immédiatement** : les providers propagent les changements d'accès avec un délai, et l'agent agit dans cet intervalle.

## Où est le trou

La couverture vendor est la plus profonde en **ES|QL Elastic** et la plus faible en **Sigma, Splunk et Sentinel KQL**. Les comportements sont documentés ; les règles portables ne le sont pas. C'est la recherche originale la moins chère qu'un praticien puisse publier.
