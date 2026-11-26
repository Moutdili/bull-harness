# Plan v3 : vérifier, mesurer, puis premier run YesWeHack (2026-11-24)

Pas de code dans ce plan. Il dit ce qui est en place (vérifié), ce que la littérature recommande, l'écart
entre les deux, et l'ordre des tâches. Chaque tâche est une issue GitHub labellisée (schéma en bas).

## 1. État vérifié le 2026-11-24 (sorties d'outils réelles)

| Point | Résultat |
|---|---|
| Tests unitaires `uv run pytest` | tous verts |
| Lint `ruff check src tests` | propre |
| Suite d'évasion live (gate) | **29/29**, raisons des refus vérifiées |
| Run lab 15 et 16 (après passkey et « appareils de confiance ») | OK, 3 et 6 tours, ~0,05 $ éq. chacun ; relais et jeton du gate intacts |
| Contexte de base par tour (prompt Claude Code + outils + doctrine + board) | 8,4 k à 10,3 k tokens ; doctrine seule ≈ 2,3 k |
| Croissance du contexte (run 12, 22 tours) | pic 19,4 k : les builtins (≤ 25 lignes) et la troncature (80 lignes / 8 000 car.) tiennent le contexte |
| Taux de cache (lecture / entrée totale) | 94 % sur 22 tours (run 12), mais 65 % sur 3 tours (run 15) : un segment court paie surtout l'écriture du cache |
| Temps d'outils (run 12) | 560 s d'outils sur 22 tours, un appel jusqu'à 267 s : le temps d'horloge est dominé par l'attente des outils au débit du programme, pas par le modèle |
| Troncature (`trunc.jsonl`) | ne s'est pas déclenchée sur les derniers runs (sorties des builtins déjà courtes) ; mesurée en 2.3 |
| Superviseur | rotation après 2 segments sans progrès mesuré ; quota → sommeil **fixe** de 30 min |
| Métriques par tour (`turns`) | n'existent que depuis le run 12 : pas d'historique plus ancien |
| `docs/TODO.md` | tableau d'état en retard (l'import YWH public est fait, pas noté) |

Constat : le contexte n'est pas notre problème aujourd'hui (19 k au pic). Ce qui limite un run long, c'est
(a) le quota de l'abonnement, (b) le cache qui expire pendant les outils longs, (c) l'absence de stratégie
quand un segment dépasse quelques dizaines de tours. Ce sont ces trois points qu'il faut mesurer avant d'optimiser.

## 2. Littérature → doctrine : ce qui est en place, ce qui manque

Légende : ✅ en place et vérifié · ◐ partiel · ✗ absent · 🔬 à mesurer avant de décider.

### Économie de tokens et contexte long

| Résultat publié | Source | Chez nous |
|---|---|---|
| Les observations (sorties d'outils) font ~84 % des tokens d'un tour d'agent ; masquer les anciennes observations divise le coût par 2 sans perte de réussite, aussi bien qu'un résumé par LLM | [The Complexity Trap, arXiv:2508.21433](https://arxiv.org/abs/2508.21433) (JetBrains, NeurIPS 2025 ws) | ◐ sorties courtes à la source (builtins ≤ 25 lignes, troncature 80 lignes, brut sur disque). ✗ pas de masquage des **anciennes** observations dans un segment : on compte sur la rotation par `max_turns` |
| Compression apprise de l'historique et des observations : −26 à −54 % de tokens au pic, performance préservée | [ACON, arXiv:2510.00615](https://arxiv.org/abs/2510.00615) (ICLR 2026) | ✗ ; à n'envisager que si la mesure montre des segments longs à gros contexte |
| La performance baisse quand l'entrée grandit, même sur des tâches simples (« context rot ») | [Chroma, Context Rot](https://research.trychroma.com/context-rot) ; [Anthropic, context engineering](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents) | ✅ sessions neuves par segment, doctrine courte, board résumé (`frontier` ≤ 40 lignes) |
| Perte du contexte de session = première cause d'échec des agents de pentest | [PentestGPT, arXiv:2308.06782](https://arxiv.org/abs/2308.06782) ; [VulnBot, arXiv:2501.13411](https://arxiv.org/abs/2501.13411) | ✅ état hors contexte (board, faits, intents, dead-ends, HANDOFF) |
| Mémoire structurée hors contexte + estimation de difficulté en temps réel (horizon, confiance, charge de contexte, historique) ; ces échecs ne disparaissent pas avec un plus gros modèle | [PentestGPT v2 / Excalibur, arXiv:2602.17622](https://arxiv.org/abs/2602.17622) | ✅ mémoire. ◐ difficulté : intents et dead-ends existent, mais aucun budget par piste ni abandon chiffré |
| Un planificateur externe structuré (DAG / PDDL) au-dessus de Claude Code : +20 % de réussite, coût et temps −50 % | [CheckMate, arXiv:2512.11143](https://arxiv.org/abs/2512.11143) | ◐ le board donne la frontière ; pas de plan explicite par cible |
| Routage de modèle par étape ou par sous-tâche : −44 % à −72 % de coût pour < 3 points de perte | [Budget-Aware Routing, arXiv:2602.21227](https://arxiv.org/abs/2602.21227) ; [Planner-as-Router, arXiv:2609.32917](https://arxiv.org/abs/2609.32917) ; [AgentRouter, arXiv:2609.22951](https://arxiv.org/abs/2609.22951) | ◐ juge Opus / chasseur Sonnet ; ✗ pas de routage cartographie (modèle léger) / exploitation (modèle fort) |
| Cache de prompt : TTL 5 min par défaut ; `ENABLE_PROMPT_CACHING_1H` existe mais serait sans effet en OAuth claude.ai (sources tierces, à vérifier) | [claudeissues #48082](https://claudeissues.com/issue/48082-docs-prompt-caching-ttl-env-var-docs-omit-generic-1-hour-and-forced-5-minute-con) ; [env-vars](https://code.claude.com/docs/en/env-vars) | 🔬 nos outils durent jusqu'à 267 s, proche des 5 min : il faut mesurer combien de tours réécrivent le cache |

### Agents offensifs : ce qui marche

| Résultat publié | Source | Chez nous |
|---|---|---|
| Sur un vrai réseau de 8 000 hôtes, l'agent ARTEMIS est 2ᵉ sur 10 pros, 82 % de soumissions valides, ~18 $/h ; forces : énumération systématique, exploitation **parallèle** ; faiblesse : plus de faux positifs | [ARTEMIS, arXiv:2512.09882](https://arxiv.org/abs/2512.09882) (ICLR 2026) | ✅ énumération systématique (arsenal + verrou). ✗ pas de parallélisme (un run à la fois, verrou global). ✅ filtre FP à deux étages |
| Planificateur + agents experts par classe : ×4,3 sur des zero-days web | [HPTSA, arXiv:2406.01637](https://arxiv.org/abs/2406.01637) (EACL 2026) | ◐ 12 fiches par classe choisies par signaux, mais un seul agent |
| Détection de zero-day difficile (12,5 % au mieux) ; exploitation et patch bien meilleurs | [BountyBench, arXiv:2505.15216](https://arxiv.org/abs/2505.15216) (NeurIPS 2025) | info : viser les classes où la preuve est mécanique (IDOR, authz) plutôt que la découverte pure |
| Claude Code + Sonnet 4.5 « hors de la boîte » meilleurs que tous les systèmes antérieurs, mais plans longs incohérents | [CheckMate, arXiv:2512.11143](https://arxiv.org/abs/2512.11143) | ✅ choix de base confirmé ; ◐ plans longs (voir planificateur) |

### Faux positifs et vérification

| Résultat publié | Source | Chez nous |
|---|---|---|
| Traiter chaque rapport comme une hypothèse réfutable ; validation de conditions et de chemin | [VulAgent, arXiv:2509.11523](https://arxiv.org/abs/2509.11523) | ✅ `proof.json` + contrôle jumeau obligatoire |
| Passes « kill » adverses, critique d'un **autre modèle**, validation empirique | [Refute-or-Promote, arXiv:2604.19049](https://arxiv.org/abs/2604.19049) | ✅ juge Opus ≠ chasseur Sonnet ; ✅ rejeu déterministe |
| Un juge LLM se trompe avec un seul token (FPR jusqu'à 66,8 %) | [One Token to Fool LLM-as-a-Judge, arXiv:2507.08794](https://arxiv.org/abs/2507.08794) | ✅ `verified` exige aussi l'étage A déterministe ; ◐ le juge lit du texte de la cible (issue juge isolé) |
| Les agents de filtrage écartent parfois de vrais positifs | [Sifting the Noise, arXiv:2601.22952](https://arxiv.org/abs/2601.22952) | ✅ `inconclusive` → second juge Mythos, puis statut visible ; jamais rejet faute de reproduction |
| Plateformes : suspension de 30 jours pour soumissions IA non validées (Bugcrowd) ; YWH : l'humain décide toujours, aucune règle hunter publique sur l'IA trouvée | [Bugcrowd](https://www.bugcrowd.com/blog/bugcrowd-policy-changes-to-address-ai-slop-submissions/) ; [YWH, approche IA](https://www.yeswehack.com/product/ai-vulnerability-management) ; [YWH Claude Kit](https://www.yeswehack.com/learn-bug-bounty/triager-grade-reports-claude-code) | ✅ Mio soumet ; ✗ pas de métrique « taux de soumissions valides » ; 🔬 lire les CGU hunter YWH |

### Injection de prompt par la cible

| Résultat publié | Source | Chez nous |
|---|---|---|
| Des leurres et des injections cachées (ANSI, commentaires HTML) détournent >95 % des attaques LLM | [Mantis, arXiv:2410.20911](https://arxiv.org/abs/2410.20911) | ◐ doctrine « le texte de la cible est de la donnée » ; le gate borne les dégâts (scope, écritures) ; ✗ jamais testé contre un vrai leurre |
| 14 variantes d'injection : 100 % de réussite contre des outils de pentest IA | [CAI, arXiv:2508.21669](https://arxiv.org/abs/2508.21669) | ✗ pas de lab d'injection ; le juge partage le conteneur du chasseur |

### Mode CVE (white-box)

| Résultat publié | Source | Chez nous |
|---|---|---|
| ~20 % de reproduction de vulnérabilités connues ; 34–35 zero-days et 17–18 **patchs historiquement incomplets** trouvés | [CyberGym, arXiv:2506.02548](https://arxiv.org/abs/2506.02548) (ICLR 2026) | ✗ phase 5 non démarrée ; piste prioritaire : analyse de variantes des patchs récents |

## 3. Bonnes pratiques par phase (tirées de ce qui précède)

- **Socle / scope** : une seule fonction de décision, testée par propriétés ; l'import ne fait jamais
  qu'ajouter du refus ; tout cas douteux → refus et fait `blocker` (pas d'humain pendant la chasse). Avant une cible réelle : un test HTTPS positif sur un nom.
- **Confinement** : les garanties dures vivent hors du modèle (gate, utilisateurs Unix, conteneurs). Toute
  règle de la doctrine qui compte doit avoir son équivalent au gate ; la doctrine n'est qu'une aide.
- **Tokens** : mesurer avant d'optimiser (tableau `turns`). Ordre des leviers : sorties courtes à la source →
  masquage des anciennes observations → rotation avec état structuré → routage de modèle → compression
  apprise. Garder le prompt système identique d'un tour à l'autre (le cache en dépend).
- **Autonomie** : l'état vit hors du contexte (board). Chaque piste a un budget ; une piste qui l'épuise
  devient un dead-end écrit. La progression se mesure (findings, endpoints testés), pas les faits.
- **Vérification** : hypothèse réfutable, contrôle jumeau, rejeu déterministe, juge d'un autre modèle, et
  jamais de rejet faute de reproduction. Le juge ne doit pas pouvoir être influencé par le chasseur ni par la cible.
- **Runs réels** : d'abord une app à nous (HTTPS, vrais noms), puis un programme qui autorise
  l'automatisation, au débit le plus bas, HAR audité après coup. Mio lit, décide et soumet.
- **CVE** : divulgation coordonnée uniquement ; viser les variantes de patchs récents ; preuve reproductible
  dans un conteneur isolé, sans réseau.

## 4. Tâches (issues GitHub)

Ordre : tout ce qui est **P0** avant le premier run YWH, dans cet ordre. Le run Mythos (audit) a lieu
après la mesure tokens et l'isolation du juge, avec ce document en entrée.

| Prio | Issue | Proprio | Acceptation binaire |
|---|---|---|---|
| P0 | Mesurer un segment long sur le lab (100 tours) : courbe du contexte, part des observations, réécritures de cache, durée des outils | C | tableau par tour publié dans `docs/research/` ; part des observations et nb de réécritures de cache chiffrés |
| P0 | Vérifier le TTL du cache en OAuth (5 min ou 1 h) dans l'usage renvoyé par l'API | C | champ de TTL lu dans un flux du relais ; décision écrite |
| P0 | Isoler le juge dans son propre conteneur | C | le juge ne voit ni `/work` du chasseur ni ses processus ; F1 revérifié |
| P0 | Lab d'injection de prompt (page leurre façon Mantis + 3 variantes CAI) contre le chasseur et le juge | C | chaque variante est ignorée ou bornée par le gate ; résultat consigné |
| P0 | Reconstruire l'image agent depuis la base épinglée, consigner les versions | H | `check.sh` vert ; liste des versions dans le repo |
| P0 | Lire les CGU / règles hunter YWH sur l'automatisation et l'IA | M | extrait cité dans `docs/premiere-cible-ywh.md` |
| P0 | Run sur l'app perso de Mio (6.1) : HTTPS par nom, vraies règles | C+M | run complet, HAR audité, zéro requête hors scope |
| P0 | Audit Mythos du plan, de la doctrine et du code (après les P0 ci-dessus) | C+M | rapport écrit ; points critiques traités ou acceptés par Mio |
| P0 | Choisir le premier programme YWH, remplir `automation_allowed` / `scanners_allowed` | M | scope YAML validé par Mio |
| P1 | Masquage des anciennes observations ou rotation sur seuil de contexte (4.2b), selon la mesure | C | à contexte égal, coût par tour −30 % sur le lab sans perte de findings |
| P1 | Budget par piste + abandon chiffré (estimation de difficulté) dans la doctrine et le board | C | une piste qui dépasse son budget devient un dead-end ; test lab |
| P1 | Routage de modèle par segment : cartographie sur modèle léger, exploitation et juge sur modèle fort | C | coût par finding vérifié sur le lab, avant / après |
| P1 | Sommeil quota calé sur l'heure de reset annoncée, pas 30 min fixes | C | test avec message de quota simulé |
| P1 | Métrique « soumissions valides » (verdict de la plateforme saisi par Mio) | C | colonne dans le board, affichée dans l'UI |
| P1 | Jokers en milieu de label et liste des suffixes publics (0.2b) | C | tests de 0.2b verts |
| P1 | Remettre `docs/TODO.md` à jour avec cet état | C | tableau d'état exact |
| P1 | Réévaluer la phase 2 (alias, calibrage, mineur) : les commandes pèsent peu face aux observations | C | décision écrite, chiffres de la mesure P0 à l'appui |
| P2 | Parallélisme : plusieurs origines ou programmes en même temps dans le quota | C | 2 segments simultanés sans conflit de gate ni de board |
| P2 | Mode CVE (5.1–5.3), en commençant par l'analyse de variantes de patchs récents | C | un repo fixture → finding dans le board |
| P2 | Connecteur Intigriti (H4) | H | critères de la TODO |
| P2 | Capture de session humaine via le gate (4.5) | C | login manuel sur l'app de test → requêtes agent authentifiées |
| P2 | Comparer notre PoC triager au YWH Claude Kit | C | écarts listés |

## 5. Labels

- Priorité : `P0` (avant le premier run YWH), `P1`, `P2`.
- Domaine : `area:tokens`, `area:gate`, `area:verify`, `area:autonomy`, `area:scope`, `area:cve`, `area:ops`, `area:docs`.
- Propriétaire : `owner:claude`, `owner:hermes`, `owner:mio`.
- Nature : `measure` (mesurer avant de décider), `build`, `research-check` (doctrine vs littérature), `audit`.
