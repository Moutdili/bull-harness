# Relecture des trois skills MSRC

## Résumé

- **Fidélité bonne.** J'ai relu une à une les citations des trois `talk-notes.md` : toutes sont dans les transcriptions. Aucun montant, date, règle ou nom d'API inventé et attribué à un orateur.
- **Écarts dans les `SKILL.md`.** Des déductions ne sont pas étiquetées, quatre citations sont lissées, quelques formulations sont trop fortes.
- **Un bloquant**, dans la section 6 de `ai-red-team-pyrit` : le chemin « navigateur » vers Copilot ne passe ni `bh-browse` ni le gate tels qu'ils sont.
- **Hors bande.** Les trois skills supposent un récepteur à nous. `bh-oob` n'existe pas (issue 31 ouverte) : le chasseur finira sur `oob-needed`.
- **Portée.** Le chasseur ne charge pas `.claude/skills`. Il reçoit des cartes (`src/bh/cards/`, 13 cartes, aucune sur l'IA). Ces skills ne servent aujourd'hui qu'à l'orchestrateur.
- **Omissions principales.** Plugins Dataverse (Copilot Studio), exemples cités déjà corrigés (AI bounty), arrêt sur exécution côté serveur (PyRIT).
- **Non vérifié.** Les faits PyRIT étiquetés `[repo]` et les pages MSRC (réseau interdit).

Conventions : T1, T2, T3 = les trois transcriptions, `l.N` = ligne du fichier brut. **V** = vérifié dans la source ou le code. **S** = supposé.

## 1. msrc-copilot-studio-research (source T1)

| Gravité | Fichier:ligne | Constat | Preuve | Correctif |
|---|---|---|---|---|
| important | SKILL.md:50 | Titre « classes the speaker called valid » trop fort. L'orateur ne dit « primable » que pour trois cas. Le reste est « interesting » ou simplement cité (modération par langue, fichiers, code des connecteurs). V | T1 l.8 « highest bounty award », « could be bountiable » ; l.16 « would be a bounty bull find » ; l.16 « we have SSRFs… or… file abuse » | Renommer « pistes citées ». Ajouter une colonne « verdict de l'orateur » : primable, intéressant, cité. |
| important | SKILL.md:39-40 ; talk-notes.md:22 | Omission du seul succès concret du talk : plusieurs critiques trouvés via les plugins Dataverse (extensibilité pro-dev, SDK), et le SSRF comme spécialité du même chercheur. Les notes ne gardent que « Eric : nom non vérifié ». V | T1 l.10 « leverage, yeah, dataverse plugins to file several… critical vulnerabilities » ; l.18 « That's what Eric was very good at finding » | Ajouter la ligne « plugins Dataverse / SDK » en tête du tableau §2 et dans la méthode. |
| important | SKILL.md:117-119 | Étape SSRF : « reaches non-public addresses » invite à viser des adresses internes de Microsoft. Le talk ne donne aucune limite et la skill ne cite aucune règle. V pour l'absence ; règle MSRC : S | T1 l.16 « we have SSRFs… when I'm reaching out and talking to those URLs » ; l.18 « stay within the bounty… rules of engagement » | Borner : la preuve est la requête reçue chez nous. Aucune adresse interne ni métadonnée avant lecture de `pentest-rules-of-engagement` par Mio. |
| important | SKILL.md:142-143 | Donnée d'un tiers vue par accident : « report to MSRC immediately ». Pendant la chasse il n'y a pas d'humain, et la skill ne donne aucun geste harnais. V | T1 l.18 « let us know immediately so we can contact our customers… the last thing we need is… a security incident from research » | Écrire le geste : arrêt du programme, aucune relecture de la donnée, fait dédié, alerte à Mio. À créer côté harnais. |
| important | SKILL.md:66 ; §5 | Connecteurs custom et plugins exécutent du code. Aucune règle d'arrêt en cas d'exécution côté serveur. T1 n'en parle pas, T3 oui. V dans T3 | T3 l.10 « if you get… server side execution… reach out to bounty@microsoft.com… don't go beyond proof of concept » | Ajouter l'arrêt, étiqueté « source : vidéo PyRIT ». |
| mineur | SKILL.md:56 ; talk-notes.md:143 | « named the biggest cross-tenant risk » et titre « top cross-tenant paths » : l'orateur dit moins. V | T1 l.18 « I think SSRF is, is probably one of the biggest risks » | Reprendre « probably one of the biggest ». |
| mineur | SKILL.md:21, 24 | « from most to least valuable (speaker's ordering) » : l'ordre de valeur n'est dit que pour tenant puis environnement. La suite suit la diapositive. « is bountiable » au lieu de « could be ». V | T1 l.8 « After that… the environment… could be bountiable. And then as we move down… » | Limiter l'ordre aux deux premiers. Écrire « could be ». |
| mineur | SKILL.md:37, 113, 44, 94 | « test pane » : 0 occurrence dans T1. « tenant switch » est une déduction, et la ligne 94 l'active par environnement. V | T1 l.10 « You can use the tracing mode… » ; l.16 « you can go into PPAc and you turn that off » | Étiqueter « inferred ». Trancher tenant ou environnement sur la doc. |
| mineur | SKILL.md:83-128 | Les §4 à §6 sont surtout notre construction (deux tenants, canaris, import ALM comme contournement, HAR). Rien ne le dit, sauf pour les licences. L'orateur écarte même l'ALM. V | T1 l.16 « not so much related to… the Copilot Studio itself » | Une ligne en tête de §4 : « méthode déduite, pas dans le talk ». Marquer l'étape 7. |
| mineur | SKILL.md:103 | « the operator provides tokens; do not automate credential entry » : ni dans T1 ni dans doc 15. Contredit le moteur d'auth (recettes `oauth_refresh` et `browser` + TOTP, doc 16). V | absent de T1 | Renvoyer à `bh accounts` et doc 16. Laisser à Mio la décision sur le login Entra par navigateur. |
| mineur | SKILL.md:47-48 | STRIDE inclut le déni de service, interdit par MSRC (doc 15). V | T1 l.18 « spoofing, tampering… denial of service » | Ajouter « sans le D ». |
| mineur | SKILL.md:52-66 | Pistes absentes du tableau : initié malveillant, IdP custom comme entrée d'attaque, empoisonnement des sources. V | T1 l.14 « identity abuse by… being a malicious insider » ; l.12 « use a custom IDP to present risk to… the platform » ; l.14 « trying to poison the system » | Ajouter trois lignes. |
| mineur | SKILL.md:61 | Abus du consentement = hameçonnage zéro clic. Risque de glisser vers l'ingénierie sociale, interdite. V | T1 l.18 « abused for a zero-click fish » | Préciser : entre nos deux comptes seulement. |
| mineur | talk-notes.md:13 | « content is missing at each cut » non démontré. Plusieurs coutures se recollent sans perte visible. V | T1 l.16/18 « unauthen » / « unauthenticated » ; l.18/20 « strings. » / « concatenation » | Écrire « coupure de bloc, perte possible ». |
| mineur | SKILL.md:3 | Description : Power Pages, Power Automate, AI Builder et Dynamics 365 ne déclenchent pas. | — | Les ajouter. |

## 2. msrc-ai-bug-bounty (source T2)

| Gravité | Fichier:ligne | Constat | Preuve | Correctif |
|---|---|---|---|---|
| important | SKILL.md:41 | Troisième impact « reading data the victim can see but the attacker cannot » : absent du talk, présenté comme impact qui compte. V | T2 l.12 ne cite que « zero-click exfiltration of data, or performing some privileged action on behalf of the user » | Étiqueter « deduction » ou retirer. |
| important | SKILL.md:38-39 | L'exfiltration par image markdown est citée sans dire qu'elle est corrigée. Le chasseur la rejouera pour rien. Les notes (l.90) le disent, pas la skill. V | T2 l.22 « all the vulnerabilities that we talked about… have been reported to MSRC and have been fixed » | Ajouter « corrigé : chercher une variante (autre rendu, autre canal de sortie) ». |
| important | SKILL.md:128-132, 160 | Preuve anti-hallucination par « collector you own » : pas de hors bande dans le harnais. La skill durcit aussi un conseil facultatif en champ obligatoire. V | T2 l.16 « if possible at all, if you can provide proof that the issue isn't a result of a hallucination » | Proposer d'abord des preuves sans hors bande : effet visible depuis le compte attaquant, requête hors hôte comptée par `bh-browse`. Garder « si possible ». |
| mineur | SKILL.md:68 | « jailbreak, harmful content » : 0 occurrence de « jailbreak » dans T2. Extrapolation juste, non étiquetée. La vraie source est T3. V | T2 l.12 « if you're just able to manipulate the output… content related issue » ; T3 l.10 « you don't get bounties for convincing Chat GPT… » | Citer la vidéo PyRIT. |
| mineur | SKILL.md:9, 21-22, 27-28 | Trois déductions écrites comme des faits : « first edition, late 2024 », Moderate/Low sans points, bugs classiques jugés par la barre online-services. Les notes les marquent [D], pas la skill. V | T2 l.18 « a lot of those things are already covered in our existing bug bars » (appui partiel) | Reporter le marqueur. Date probable : T3 l.8 annonce une session « AI Bug Bar » le 17 déc. 2024 (S). |
| mineur | SKILL.md:82 | Échelle « zero-click > one click > multi-step » : le talk ne sépare pas un clic de plusieurs étapes. V | T2 l.12 « click on a link or… go through one or more steps, that would decrease the severity slightly » | Deux niveaux : zéro clic, puis interaction. |
| mineur | SKILL.md:32, 49, 57 | Gravités lissées. « always hinges on… victim interaction » est faux pour la divulgation (classification des données). « low » remplace « much lower ». « lower than reconstruction » n'est dit que pour membership inference. V | T2 l.14 « a much lower severity » ; « that doesn't go up to as high a severity » | Corriger les trois formulations. |
| mineur | SKILL.md:37 | « a tool result » comme vecteur : pas dans le talk (page, courriel, document). V | T2 l.12, l.20 | Étiqueter. |
| mineur | SKILL.md:127 | Citation entre guillemets non verbatim : « 1, 10 or 100 times ». V | T2 l.16 « one one time or 10 times or 100 times » | Citer exactement ou ôter les guillemets. |
| mineur | SKILL.md:70-72 | Extraction du prompt système : aucune exception. T3 en donne une, et `ai-red-team-pyrit/SKILL.md:90` la reprend. Incohérence entre skills. V | T3 l.10 « if they apply to a specific user and there's confidential information there, please… send us a case » | Ajouter l'exception, source étiquetée. |
| mineur | SKILL.md:155 | « Re-read bounty-ai… » : impossible pour le chasseur, qui n'a pas le web. V | `docs/architecture.md` (relais, MCP) | Marquer « orchestrateur, avant le run ». |
| mineur | SKILL.md:112 | TaskTracker et « content issues… can lead to more security vulnerabilities » ne sont que dans les notes. V | T2 l.20, l.22 | Une ligne chacun, ou rien. |
| mineur | SKILL.md:12 | URL `microsoft.com/msrc/bounty-ai` : pas dans le talk, non vérifiée ici. | — | Marquer « non vérifiée ». |

## 3. ai-red-team-pyrit (source T3)

### Fidélité, omissions, sûreté

| Gravité | Fichier:ligne | Constat | Preuve | Correctif |
|---|---|---|---|---|
| important | SKILL.md:85 | « Rate-limit bypass » rangé sous « Pays ». Le talk ne dit pas que c'est primé. Le chercher, c'est dépasser la limite, donc sortir de la règle sur le trafic excessif. V | T3 l.10 « If you're able to bypass the rate limiting, by all means uh let us know but don't use that capability… » | Sortir de « Pays ». Écrire « ne pas chercher ; signaler si vu par hasard ». |
| important | SKILL.md:57-76 | Deux règles du talk absentes de la skill, présentes dans les notes : arrêt sur exécution côté serveur, respect des contrats de service. V | T3 l.10 « reach out to bounty@microsoft.com if you want additional guidance on should you proceed » ; « does not violate our service agreements » | Les ajouter aux préconditions de §3, avec le geste harnais (arrêt + fait pour Mio). |
| important | SKILL.md:67-71, 108, 149 | Canari « fetch a URL on an endpoint we own », « OOB log » : composant inexistant. V | `docs/issues/031-…` ; `src/bh/agent/contract.py:77` | Voir constats communs. |
| mineur | SKILL.md:26 | `PromptSendingOrchestrator` et `CrescendoOrchestrator` étiquetés [talk]. Seules les formes parlées sont dans la source. V | T3 l.12 « prompt sending orchestrator », « a Crescendo orchestrator » | Étiqueter la graphie de classe comme déduite. |
| mineur | SKILL.md:26, 30, 47 | Trois citations lissées. V | T3 l.12 « the one component that that's not an interface » ; l.12 « a a common way to say like was this attack successful » ; l.18 « a really good place to to dig » | Citer exactement ou ôter les guillemets. |
| mineur | SKILL.md:33 | « the objective target » : 0 occurrence dans T3. V | T3 l.12 « Here we have a target… We give it the adversarial chat, our scoring target » | Retirer du [talk]. |
| mineur | SKILL.md:14-18, 26-31, 106 | Faits `[repo]` (dépôt déplacé, v1.2.1, classes, blog) : hors transcription, invérifiables ici. Ils sont bien étiquetés. | — | Garder le §7. Revérifier à l'installation. |
| mineur | talk-notes.md:34-37 | La classification de Martin est reprise sans alerte. Elle contredit l'auteur de la barre : vol de modèle rangé en « model manipulation », gravité « critical… if not… important ». V | T3 l.8 ; T2 l.14 « ranges from low all the way up to to critical » | Ajouter « approximatif : msrc-ai-bug-bounty fait foi ». |
| mineur | SKILL.md:76 | « Reproduce twice » contre « k/N » et identifiant de conversation dans l'autre skill. V | T2 l.16 | Renvoyer à msrc-ai-bug-bounty §6. |
| mineur | SKILL.md:50-52, 102-103 | La règle « harm objectives » n'exclut pas les gabarits de jailbreak (DAN). Risque de refus du chasseur, tier Defense. S | T3 l.14 « Pirate's got a couple hundred simple jailbreaks » | Exclure le dataset jailbreak et `TextJailbreakConverter` des recettes v1. |
| mineur | SKILL.md:114 | « PyRIT executes LLM output as data » : affirmation sans source. | — | Retirer ou sourcer. |
| mineur | SKILL.md:3 | Description large, recoupe msrc-ai-bug-bounty sur « jailbreak bounty-grade ». | — | Laisser ce tri à l'autre skill. |

### Section « Integrating with bull-harness » (faisabilité)

| Gravité | Fichier:ligne | Constat | Preuve (harnais) | Correctif |
|---|---|---|---|---|
| bloquant | SKILL.md:129-131 | Chemin « navigateur » irréalisable tel quel. `bh-browse` lance un Chromium par commande, donc aucune page persistante à donner à `PlaywrightTarget`. Il coupe toute requête hors hôte cible et refuse les websockets, que le gate refuse aussi. Si l'UI Copilot parle en websocket, aucun tour de chat ne passe. Refus : V. Dépendance de Copilot aux websockets : S, appuyée par l'URL `wss://` que la skill cite. | `src/bh/gate/addon.py:491-492` ; `src/bh/agent/browse.py:1-13` | Mesurer d'abord à la main le transport de l'UI visée. Si websocket : décision de Mio (jugement des trames dans le gate, ou cible écartée). Vaut aussi pour la recommandation de doc 15. |
| important | SKILL.md:121-123, 166 | « the judge replays the recipe and sees the same oracle hit » est optimiste. La cible est un LLM non déterministe. L'étage A rejoue les écritures une seule fois. Le rejeu double le trafic vers la production. V côté harnais | `docs/architecture.md` §7 | Fixer un seuil k/N, un budget de rejeu, et qui rejoue l'écriture (le mail de A). |
| important | SKILL.md:151-156 | `ClaudeChatTarget` via le relais : à exclure, pas seulement « not recommended ». Le relais n'injecte que le jeton OAuth de Claude Code, juge betas, modèle et corps, et compte sur le budget du run. Relais : V. Rejet d'un client LiteLLM par Anthropic : S. | `addon.py:412-457` ; `policy.py:497-505` | Écrire « exclu ». |
| important | SKILL.md:118-119, 146-150 | En mode par défaut (aucun LLM), PyRIT n'apporte que des convertisseurs déterministes. En face : une grosse dépendance tierce dans l'image et une API qui a déjà cassé (SKILL.md:109). Poids des dépendances : S. | `docs/architecture.md` §5 | v1 sans PyRIT : quatre convertisseurs natifs dans `bh-agent` (Base64, balises Unicode, texte en image, PDF). PyRIT seulement si le multi-tours devient nécessaire. |
| important | SKILL.md:163-166 | Acceptation sur un « assistant » local. Il faut un LLM pour le jouer, non précisé ; un faux à regex ne teste que la tuyauterie. Et un lab HTTP n'exerce ni le proxy ni la CA du gate en TLS : angle mort déjà connu. V | SKILL.md:128 le reconnaît sans le tester | Ajouter un test HTTPS positif à travers le gate. Dire quel modèle joue l'assistant et sur quel budget. |
| important | SKILL.md:140-143 | Risque absent : le juge lira des charges d'injection écrites par le chasseur et des réponses de cible stockées dans `raw/pyrit/`. Le résumé à 25 lignes est sain, `recipe.json` et les réponses non. V côté harnais | `docs/architecture.md` §7 et limite « Vérificateur » | Passer charges et réponses au juge comme données balisées et bornées. Seul l'oracle déterministe décide. |
| mineur | SKILL.md:135-138 | Classer `bh-pyrit` « outil de test » sous `scanners_allowed: false` est une lecture des règles MSRC, pas un choix technique. Aucun seuil publié. Le talk admet l'outil dans les limites de débit. V | T3 l.10 « abide by the rate limiting » ; `contract.py:30-33` | Décision de Mio, notée dans le scope. Plafond par jour, pas seulement par appel. |
| mineur | SKILL.md:126-128 | « never passed to PyRIT » vaut pour les cookies. L'en-tête `X-BH-Identity` doit, lui, être posé par la recette. Le lien avec le « HAR flow id » n'est pas spécifié. V | `contract.py:55` ; `browse.py:493` | Préciser les deux. |
| mineur | SKILL.md:132-133 | Injection par mail ou fichier : suppose un Copilot qui lit la boîte de B, donc une licence probable (blocker `paid`). Comptes de test exposés au bridage. S | — | Le dire. Prévoir l'arrêt sur bridage du compte. |

Points sains de cette section : aucun LLM par défaut, aucune clé dans l'agent, recettes au lieu de Python libre, sortie à 25 lignes, `WebSocketCopilotTarget` écarté, modèle tiers renvoyé à une décision de Mio.

## Constats communs aux trois skills

- **Le chasseur ne les voit pas (important).** Aucun code de `src/` ne charge de skill (grep). `src/bh/stack.py:152-181` efface `~/.claude` entre sessions. La méthode arrive par cartes, et aucune ne couvre l'IA. La tâche 4.6 de `docs/TODO.md` (skills en liste blanche) n'est pas faite. Correctif : une carte `prompt-injection` d'une page, distillée des trois skills.
- **Hors bande (important).** Lignes concernées : copilot-studio 96-98 et 117 ; ai-bug-bounty 130-132 ; pyrit 67-71. Tant que l'issue 31 est ouverte, écrire dans chaque skill l'alternative sans récepteur et le blocker `oob-needed`.
- **Doublons.** « Ce qui paie » est écrit trois fois, avec un écart (exception du prompt système). Le rapport est décrit trois fois ; la version d'ai-bug-bounty est la plus complète. Deux noms de canari : `MSOBB-CANARY-…` et `BH-CANARY-…`. Les deux skills MSRC ne se citent pas entre elles.
- **Lien de soumission.** T2 donne « aka.ms/secure-ai », T3 « aka.ms/secure-at ». Les deux skills le signalent comme douteux : n'en utiliser aucun.
- **Doc 15 à compléter** par l'orchestrateur : outil automatisé admis sous les limites de débit (T3), arrêt sur exécution serveur (T3), champs de rapport IA (T2), signalement immédiat d'une donnée tierce (T1).

## Ce qui est bon

- Citations des notes exactes, disfluences comprises. Les erreurs de transcription sont listées et corrigées prudemment (« bounty bull », « Pirate », « holy control », « Integrity »).
- Le lapsus de T2 (« input extraction is now not in scope ») est repéré et traité correctement.
- Chaque skill sépare talk, doc 15 et déduction dans ses notes, et a une section « pas dans le talk ». La skill PyRIT dit que la mémoire n'est pas abordée. La skill Copilot Studio dit qu'aucune licence n'est citée.
- Datation claire : chiffres de 2024 (×2, 30 000 $, « mid January ») marqués périmés face au +50 % de doc 15.
- Règles cohérentes avec le harnais : deux identités à nous, compte peu privilégié, canari bénin, arrêt à la preuve, pas de scanner, relecture humaine.
- Aucune charge offensive prête à l'emploi. Aucun texte d'injection, aucune cible tierce.
- Descriptions précises ; elles déclenchent au bon moment pour l'orchestrateur.

## Limites

- Aucune requête réseau. Non vérifiés : pages MSRC, liens `aka.ms`, dépôt PyRIT (version, classes, blog), vidéos elles-mêmes. J'ai comparé les skills aux transcriptions, qui peuvent être fausses.
- Citations vérifiées par lecture, pas par script. Les repères de position des notes (%, `L<n>` par `fold`, minutes) ne sont pas vérifiés : la commande a été refusée par les permissions.
- Côté harnais : lu `docs/architecture.md`, doc 15, le début de doc 16, `contract.py`, le relais et le refus des websockets dans `addon.py`, l'en-tête de `browse.py`, la liste des cartes. Rien n'a été exécuté.
- Suppositions marquées S : transport websocket des UI Copilot, rejet du jeton OAuth hors Claude Code, poids des dépendances PyRIT, position de MSRC sur le SSRF interne et les rappels hors bande, licence requise pour un Copilot qui lit le courrier.
- Je n'ai pas testé le chargement réel des skills ni leur déclenchement par description.
