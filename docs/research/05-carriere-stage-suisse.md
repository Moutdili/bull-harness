# 05 — Carrière, stages et marché suisse

---

## 1. Les quatre pistes de monétisation

Ordonnées par vitesse de cash.

### Piste 1 — Bug bounty IA (2-8 semaines)

| Programme | Montant | Particularité |
|---|---|---|
| **0din (Mozilla)** | 500 – 15 000 $ | Abstract d'abord, **réponse de scope en 3 jours ouvrés**. Paie explicitement le « Execute Violation » (prompt injection → exécution) en HIGH→SEVERE. Meilleur point d'entrée |
| **OpenAI Safety BB** (Bugcrowd) | jusqu'à 7 500 $ | Risques **agentiques + MCP** explicitement dans le scope |
| **OpenAI Security BB** | 30 000 $ critique, jusqu'à 172 000 $ avec bonus | Cœur de produit : ChatGPT, Codex, API |
| **Google AI VRP** | 20 000 $ base (S1 Rogue Actions), 30 000 $ avec multiplicateurs | VRP classique : RCE à 101 010 $ |
| **Meta GenAI** | jusqu'à 130 000 $ | Prompt injection seul **non payable** — il faut chaîner |
| **Anthropic** | jusqu'à 35 000 $ | Universal jailbreak, **invite-only** |
| **xAI** | jusqu'à 20 000 $ | — |

Surface la moins saturée : **serveurs MCP et intégrations d'agents** (tool-call abuse, SSRF via outils, exfiltration de contexte).

### Piste 2 — Detection engineering (récurrent)

**SOC Prime Threat Bounty.** Payout à l'usage, pas à la publication : le rating dépend du nombre de clients uniques qui déploient la règle. Chiffres publiés par eux-mêmes (historiques, 2022) : **moyenne ~1 360 $/mois** pour un contributeur actif, **top 2 800 $**. Ce n'est pas un salaire — c'est un portfolio qui paie.

### Piste 3 — Conseil PME suisses (plus haut CHF/heure)

⚠ **Ne pas vendre au tarif dev web.** Un audit sécurité se facture **1 200 – 2 000 CHF/jour** en indépendant. Deux marchés différents.

Offre : **« audit d'exposition des agents IA »** — panels PentAGI / Cairn / CyberStrikeAI / ARTEX exposés sans auth (Odin : 340 endpoints PentAGI sur Internet, 22 confirmés), serveurs MCP sans authentification, agents avec accès production. Forfait **2 500 – 4 500 CHF** les 3 jours.
Distribution : **DATK et ses 592k leads suisses**.

### Piste 4 — Emploi (plancher le plus haut, le plus lent)

| Employeur | Poste | Rémunération |
|---|---|---|
| **Google DeepMind Zurich** | Senior Security Engineer, Agentic Red Team | **144 000 – 208 000 CHF** (5+ ans requis) |
| **Check Point Zurich** (ex-Lakera) | Red Team — génération d'attaques contre agents | — |
| **Vontobel** (Zurich) | AI-Security Engineer | — |
| **D-one** (Zurich) | Stage red teaming LLM → consultant | — |
| **Kudelski Security** | voir §2 | 82 – 149 k CHF selon rôle |

---

## 2. Dossier Kudelski Security

### Carte d'identité
- Division cybersécurité du **Kudelski Group** (SIX: KUD.S), groupe fondé en **1951** (magnétos NAGRA). Chairman & CEO : **André Kudelski**.
- Kudelski Security créé en **2012** avec 80 experts. Aujourd'hui : **~400 consultants**, **4 Cyber Fusion Centers**, **2 R&D centers** (Suisse + Inde), **2 labs** (Suisse + France), **1M+ assets managés**, **2000+ clients**.
- Siège international : **Cheseaux-sur-Lausanne**. Siège US : Phoenix, AZ. Bureaux : Madrid, Paris, Munich, Londres, Adliswil, Dallas, Atlanta, Bangalore, Singapour, Taipei.
- CEO de la division : **David Chétrit**.
- Acquisitions : Milestone Systems (Minneapolis, 2016) → entrée US ; M&S Technologies (Dallas, 2017) ; CFC Madrid (2022). SKIDATA cédé en 2024.

### Chiffres
- Groupe 2025 : **371,0 M$** de revenus, EBITDA **-15,6 M$**, perte nette **-40,2 M$**.
- S1 2026 : **171,8 M$**, EBITDA **-11,5 M$**, perte nette **-20,3 M$**.
- **Zéro dette**, **64,3 M$** de cash au 30 juin 2026.
- Effectifs : **1 599 FTE** fin 2024 → **1 510 FTE** mi-2026. 2025 : **-175 FTE**. Février 2025 : **160 suppressions** dont **40-45 en Suisse**.
- Segment cybersécurité : **98,5 M$** en 2025 (**-9,2 %**), EBITDA **-12,0 M$**. S1 2026 : **45,1 M$** (**-8,9 %**), marge 85,1 %, **bookings MDR +69 %**, **advisory +24 %**.
- Lecture : **CA en baisse, carnet de commandes en hausse, marge en hausse.** Turnaround, pas croissance.

### Ce qu'ils font
MDR (cœur, plateforme FusionDetect, MDR ONE, 93 % de réduction de bruit revendiquée) · Advisory / incident response · Offensive Security (pentest, red team, AI application security testing) · OT/IoT (CoE créé en 2025) · Blockchain / crypto audit · **Counter Adversary Unit (CAU)**.
Partenariats : CrowdStrike (Partner of the Year 2024, International MSSP Partner of the Year 2025, Project QuiltWorks nov. 2026), Google SecOps, Microsoft.

### Virage IA
- Portfolio **AI Security** lancé en **octobre 2024** : stratégie IA, conformité **EU AI Act**, AI threat & risk assessment, AI application security testing.
- Publications **novembre 2026** : *« Machine Speed, Human Judgment: The Next Era of MDR »* (13 nov., doctrine « AI accelerates, humans decide ») et *« AI Can Find More Vulnerabilities. Can It Reduce More Risk? »* (17 nov., par **Troy Dearing, Director of Offensive Security**, sur l'incident OpenAI/Hugging Face).
- Équipe recherche réelle : **Nathan Hamiel** (Senior Director of Research, **membre du Black Hat Review Board**, track lead IA), **Nils Amiet**.
- **Mais** : personne ne publie de télémétrie, de règles ou de dissection des frameworks agentiques. Le trou est là.

### Culture et avis
- **Glassdoor global** : **3,6/5** (97 avis), **65 %** recommandent, approbation CEO **52 %**. Work/life **4,2**, comp **3,8**, carrière **3,5**, **senior management 3,1**, outlook **45 %**.
- **Cheseaux uniquement** (8 avis) : **3,1/5**, **36 %** recommandent, **carrière 2,5**, **senior management 2,2**, **outlook 1 %**.
- Verbatim software engineer (déc. 2025) : *« Management is in panic mode and jumps on every single buzzword »*, *« no visible career opportunities, no salary evolution »*, *« 4 weeks of vacations, seriously »*.
- Verbatim cyber security engineer (fév. 2025) : *« very flexible work, good salary »* / *« management problems, direction problems »*.
- Kununu affiche 4,8/5 mais sur **une seule évaluation** → statistiquement nul.

### Salaires (CHF/an, Glassdoor Suisse, nov. 2026)
- Cyber Security Analyst **82-95 k** · Security Analyst **86-94 k** · Security Engineer **102-109 k** · Senior Security Engineer **105-139 k** · Cyber Security Expert **137-149 k** · Senior Integration Engineer **114-126 k** · Software Engineer **90-96 k**.
- Référence marché Security Engineer CH : ~**119 k** → Kudelski paie **10-15 % sous le marché** sur les profils juniors/médians.

### Recrutement — la réalité
- **15 postes ouverts, 11 en Espagne (Madrid), zéro poste sécurité en Suisse.** Les seules offres suisses « jeunes » sont des **apprentissages CFC** (ETML, CPNV) — pas des stages.
- Un seul poste suisse récent : Security Operations Engineer à Zurich, ~140 k CHF, **allemand courant + Palo Alto** requis.
- **Stages** : existent mais **non annoncés**. Preuves : témoignage officiel UNIL (*« Kudelski Security propose souvent des stages à des étudiants »*, stage → CDI), et anciens stagiaires visibles sur LinkedIn (Stage Cybersécurité Lausanne 2020, stagiaire full-stack Cheseaux 2024).

### Verdict
- **Comme employeur junior** : mitigé. Site en restructuration, avis mauvais à Cheseaux, aucun poste ouvert en Suisse. **Ne pas passer par le portail RH.**
- **Comme cible** : oui, mais par **approche directe** du CAU ou de l'Offensive Security (Troy Dearing), avec un artefact technique.
- **Drapeaux verts** : zéro dette, 64 M$ de cash, bookings +69 %, équipe recherche de niveau Black Hat, 15 minutes de Lausanne.
- **Drapeaux rouges** : trois ans de pertes, restructurations répétées, carrière 2,5/5, 4 semaines de vacances, marketing qui arrondit (1 850 employés annoncés vs 1 510 FTE réels).

---

## 3. Stage en Suisse

### Wavestone, Grand-Lancy (Genève) — la cible

**« Stage Conseil en Cybersécurité – Système multi-agents pour des tests d'intrusion assistés par IA »**

- Publié **17 sept. 2026**, encore listé / vérifié ouvert le **17 nov. 2026**.
- Concevoir et prototyper un système multi-agents **quasi autonome** conduisant des pentests sous supervision humaine, sur **Active Directory, Windows, Linux**.
- Architecture **indépendante du modèle** : un modèle par rôle (recon, exploitation, revue, contestation, rédaction), local ou API.
- Fiabilité : relecture croisée, **agents antagonistes**, rejeu déterministe, conservation des artefacts, traçabilité de bout en bout.
- Environnements : **GOAD, AWSGoat, AzureGoat**.
- **Travail préparatoire demandé** : *« État de l'art de l'outillage IA appliqué à la sécurité offensive : frameworks existants, travaux académiques, retours d'expérience publics et limites constatées. »*

→ C'est le livrable de `02-frameworks-agentiques.md`. Arriver avec, c'est arriver avec la première mission du stage déjà faite.

Deux autres stages dans la même veine au bureau suisse : **« SOC augmentés par l'IA »** et **« AI Gateway : benchmark et sécurisation de la passerelle IA »**.

### Les autres, et leur verrou

| Employeur | Verrou |
|---|---|
| **Cyber-Defence Campus** (Thun / Lausanne / Zurich) | 6-12 mois, mais **inscription dans une institution académique suisse + superviseur** requis, et **non payé par défaut** (sauf sujet marqué paid internship ou CYD Fellowship) |
| **SwissBorg** (Lausanne) | **Master EPFL** obligatoire |
| **Pictet** (Genève) | Mémoire de master, domicile Suisse |
| **Chanel** (Genève) | Convention + **crédits académiques** ↔ 42 n'a pas d'ECTS |
| **Edmond de Rothschild** | Dernière année université/HES |
| **Syz Group** (Genève) | Ouvert aux diplômés Bachelor/Master — à tenter |
| **Zurich, « Early Careers – AI Security »** | 6 mois dès mars 2027, rémunéré, entreprise non nommée — à creuser |

### Le cadre 42 Lausanne
- **Deux stages** : 4-6 mois après le tronc commun, 6 mois après la spécialisation. **Obligatoires et intégrés au cursus.**
- **42 fournit sa propre convention de stage.** L'entreprise signe un contrat de travail classique + la convention 42. Rien d'autre à fournir.
- **Le stage doit être rémunéré** pour être validé par 42.
- Phrase à mettre en premier paragraphe de chaque candidature : *« étudiant 42 Lausanne, stage de 4-6 mois intégré au cursus, convention fournie par l'école, stage rémunéré requis »*.

---

## 4. Créneau retenu

**« La personne qui détecte les frameworks offensifs agentiques. »** Étroit, brûlant, défendable. Un seul artefact alimente les quatre pistes : règles → SOC Prime, note → conférence, conférence → clients et offres, bounties → trésorerie.

### Conférences
- **Black Alps** — Yverdon-les-Bains, édition 2026 les 5-6 novembre (passée). CFP pour 2027 à surveiller.
- **Insomni'hack** — Genève, CFP hiver.
- **Swiss Cyber Storm** — Kursaal Bern, **pas de CFP** : les speakers sont invités par le comité. Il faut donc être visible avant.
