# 01 — Résumé chronologique de la conversation

Période : 13 octobre → 22 novembre 2026. Interlocuteur : Mio (0x4C6F).

---

## Séquence 1 — Les frameworks que les affiliates n'utilisent pas

**Question.** Un chercheur CTI constate qu'aucun top affiliate ransomware n'utilise ARTEX, CAIRN, CyberStrikeAI ou PentAGI, et demande de documenter ces outils (ARTEX déjà connu).

**Réponse produite.** Brief sur quatre outils + un cinquième :
- **Cairn** (`oritera/Cairn`) — moteur de résolution de problème générique, blackboard fact/intent/hint, workers = CLI d'agents de code (Claude Code, Codex, Pi) dans des conteneurs Kali. Papier arXiv 2609.32700.
- **CyberStrikeAI** (`AIPentest/CyberStrikeAI`) — Go, console d'opérateur complète : C2 intégré, WebShell manager, 100+ recettes YAML, MCP-natif, bridges Telegram/Slack/Discord.
- **PentAGI** (`vxcontrol/pentagi`) — Go, stack compose, équipe d'agents spécialisés + *reflector*, mémoire PostgreSQL/pgvector, Neo4j optionnel, sandbox Docker.
- **HexStrike** (`0x4m4/hexstrike-ai`) — pas un agent : un serveur MCP exposant ~150 fonctions offensives à l'assistant que l'opérateur utilise déjà.

**Correction apportée à la prémisse.** « Personne n'utilise » était périmé d'un trimestre :
- Unit 42 a attribué **CL-STA-1238** : 25 opérations contre 19 organisations (août-sept. 2026), accès confirmé chez 10, plus d'un million d'enregistrements exposés chez un syndicat d'enseignants américain.
- AWS a documenté un **0-day trouvé par les agents Cairn** : path traversal sur une application d'imagerie médicale, écriture de fichier en ~11 minutes, reverse shell root via `sitecustomize.py`.
- Gambit Security a documenté un opérateur **financier** : 3 harness sur des centaines de retailers, 105 projets en 5 jours, 27 entreprises compromises, 600 000 cartes, ~25 $ par cible.
- CyberStrikeAI a été corrélé par Team Cymru à la campagne **500+ FortiGate en 5 semaines** (CVE-2026-24858).

**Pourquoi les vrais affiliates ne basculent pas encore** — la réponse retenue :
1. Ce sont des moteurs d'**initial access**, pas de post-exploitation ransomware (pas d'évasion EDR, pas de Kerberoasting/ADCS outillé, pas d'encryptor ESXi).
2. Ils sont **bruyants** : scanners stock, pas de jitter, rafales de 2 à 25 s, panels exposés sans auth.
3. **Économie** : coût tokens + infra + tuning contre un toolchain déjà amorti ; ~10 % de taux de succès sur Cairn.
4. **Dépendance LLM** : télémétrie côté provider, refus de modèle, dépôt qui peut disparaître (ARTEX retiré en oct. 2026).
5. Le goulot du ransomware n'est pas le foothold mais l'accès monétisable — ils achètent à un IAB.
6. Le **skillset** : monter Compose + PostgreSQL + Neo4j filtre déjà.

**Point 3 ajouté ensuite** (Mio avait noté qu'il manquait un troisième axe) — ce qui ferait réellement basculer un affiliate :
- couverture post-exploit de bout en bout ;
- harness custom non publié des top tiers ;
- modèle **AIaaS / IAB** (vendre l'accès déjà obtenu par agent, pas l'outil) ;
- coût d'un run inférieur au prix d'un accès réseau acheté ;
- barrière d'installation (une demi-journée = filtre).

---

## Séquence 2 — Comment monétiser tout ça

**Question.** « Comment réussir à faire de l'argent, aider d'autres gens, trouver un travail ou faire du bug bounty avec tous ces outils. »

**Réponse en 4 pistes**, ordonnées par vitesse de cash :

1. **Bug bounty IA** — le plus rapide. 0din (Mozilla) : abstract, réponse de scope en 3 jours ouvrés, 500-15 000 $. OpenAI Safety BB jusqu'à 7 500 $ avec agentique/MCP explicitement dans le scope ; Security BB 30 000 $ le critique, jusqu'à 172 000 $ avec bonus. Google AI VRP : 20 000 $ base sur S1 « Rogue Actions ». Meta GenAI jusqu'à 130 000 $ mais prompt injection seul non payable. Anthropic 35 000 $ (invite-only). xAI 20 000 $.
2. **Detection engineering** — revenu récurrent. SOC Prime Threat Bounty paie à l'usage (pas à la publication) ; chiffres historiques publiés par eux : moyenne ~1 360 $/mois pour un contributeur actif, top 2 800 $.
3. **Conseil PME suisses** — plus haut CHF/heure. Ne pas vendre au tarif dev web (35 CHF/h) : un audit sécurité se facture en journées, 1 200-2 000 CHF/j. Offre : « audit d'exposition des agents IA » (panels PentAGI/Cairn/CyberStrikeAI exposés, serveurs MCP sans auth).
4. **Emploi** — plancher le plus haut, le plus lent. Google DeepMind Zurich (Agentic Red Team) 144-208 k CHF, Check Point Zurich (ex-Lakera), Vontobel, Kudelski.

**Créneau retenu.** « La personne qui détecte les frameworks offensifs agentiques. » Un seul artefact alimente les quatre pistes.

**Plan 30 jours** proposé : labo semaine 1, règles semaine 2, abstracts 0din semaine 3, note + CFP semaine 4.

---

## Séquence 3 — Kudelski : dossier complet

**Question.** « Renseigne-toi sur Kudelski, un sac d'information assez lourd pour décider si je postule. »

**Livré** (détail dans `05-carriere-stage-suisse.md`) : structure du groupe, chiffres financiers, portfolio, virage IA, avis Glassdoor, salaires, réalité du recrutement, drapeaux rouges et verts, verdict.

**Conclusion.** Pas par le portail RH. Le site de Cheseaux est en restructuration, les avis y sont mauvais (3,1/5, opportunités de carrière 2,5/5), et **aucun poste sécurité n'est ouvert en Suisse** (11 sur 15 sont à Madrid). Entrée réaliste = approche directe de l'équipe recherche / offensive security avec un artefact technique.

---

## Séquence 4 — Le stage en Suisse

**Question.** « Un stage ? En Suisse. »

**Réponse.**
- **Kudelski** : zéro stage ouvert en Suisse. Leurs seules offres jeunes sont des **apprentissages CFC** (ETML, CPNV) — pas pour un reconverti. Mais ils prennent des stagiaires hors annonce (témoignage UNIL officiel + anciens stagiaires visibles sur LinkedIn) → **candidature spontanée**.
- **Wavestone, Grand-Lancy (Genève)** : stage « Système multi-agents pour des tests d'intrusion assistés par IA ». Publié le 17 sept. 2026, encore listé le 17 nov. 2026. C'est **le** sujet : architecture multi-agents model-agnostic, AD/Windows/Linux, GOAD/AWSGoat/AzureGoat, agents antagonistes, rejeu déterministe, traçabilité. Le travail préparatoire demandé est *littéralement* l'état de l'art des frameworks offensifs IA.
- **Cyber-Defence Campus** : 6-12 mois à Thun/Lausanne/Zurich, mais inscription universitaire + superviseur académique requis, et non payé par défaut.
- **SwissBorg, Pictet, Chanel, Edmond de Rothschild** : verrouillés (Master EPFL, ECTS, convention académique).
- **Cadre 42 Lausanne** : deux stages de 4-6 mois, **rémunérés obligatoirement**, convention fournie par l'école. Ça règle l'objection « il nous faut une convention universitaire ».

---

## Séquence 5 — La télémétrie et les 15 étapes

**Question.** « Explique-moi en détail le plan, pourquoi la télémétrie, comment la récupérer, 15 étapes, sois mon prof. »

**Livré.** Définition de la télémétrie sur trois plans (hôte, réseau, applicatif), la raison technique pour laquelle une règle ne peut pas être écrite sans données (une règle Sigma est une requête sur des champs nommés), l'architecture du labo, les 15 étapes, un squelette de règle Sigma. Détail complet dans `04-plan-detection-lab.md`.

---

## Séquence 6 — Analyse du GitHub Ignitetechnologies

**Question.** Lien vers `https://github.com/Ignitetechnologies`.

**Verdict.** C'est « Hacking Articles » (New Delhi), 34 repos, 6 008 followers, compte de 2016. 90 % de cheatsheets et mindmaps, zéro repo de détection. Le repo `AI-Pentest` est un entonnoir marketing (9 Ko, 2 fichiers, créé et poussé le même jour, 6 liens vers leur blog, formulaire de formation payante).

**Pépite extraite.** Leur article du 21 juin 2026 sur **HexStrike + Claude Desktop + NetExec** :
- HexStrike est **packagé dans Kali** (`sudo apt install hexstrike-ai`, v6.0, 2,76 Mo) — ✅ vérifié sur kali.org/tools ;
- la chaîne AD complète recon → spray → Domain Admin → dump LSA/SAM/LAPS → DPAPI → persistance ;
- puis ils **repasse côté défenseur** et lisent les event logs, avec une section sur la signature DCSync (Event 4662).

Ils donnent le comportement et l'event ID. **Ils ne donnent pas la règle** : ni Sigma, ni champ, ni seuil, ni faux positifs. C'est exactement le trou identifié en séquence 1.
