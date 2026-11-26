> Plan en vigueur : v4.2, `out/roadmap-v4.md` (chemin à confirmer par l'orchestrateur) ; ce TODO le précède.
# bull-harness — TODO maître

Décisions figées (2026-11-22, plan Ultra depuis le 2026-11-24) : CVP **Defense** (individuel) · Podman rootless · YWH + Intigriti d'abord · objectif court terme : **premiers CVE** (divulgation coordonnée) → dossier Red Team plus tard.

Légende propriétaire : **C** = Claude (en direct, parties critiques) · **H** = Hermes (swarm) · **M** = Mio (humain).
Chaque tâche a un critère d'acceptation **binaire**. Une tâche n'est finie que si le critère passe en sortie d'outil réelle.

## État au 2026-11-25 (vérifié par tests ; le live reste à faire, issue 27)

| Phase | Fait | Reste |
|---|---|---|
| 0 Socle | 0.1, 0.2 (scope + 80+ tests), 0.4 board (+ migrations, reset), 0.5 CLI | 0.2b fait le 2026-11-25 (jokers mi-label, PSL embarquée, testés). 0.3 remplacé par les builtins `bh.agent.tools` (pas de manifests YAML) |
| 1 Confinement | 1.1 gate HTTP (décision sur la destination réelle, fail-closed, TCP brut coupé, méthodes, backoff 429/503/WAF), 1.1b passifs (hôtes exacts, IP publiques), 1.4 réseaux, **1.5 suite d'évasion `tests/escape/escape_check.sh` : 29/29** (HTTPS par nom, raisons des refus vérifiées) | 1.2 DNS filtrant (aujourd'hui : aucune résolution externe), 1.3 SOCKS (volontairement absent), sources passives de subfinder |
| 2 Tokens | 2.2 troncature, 2.3 `updatedToolOutput` vérifié, base par tour −62 % (`--tools Bash,Read`, sans slash commands), sessions neuves par défaut | 2.4 mineur et 2.5 calibrage faits (veille). **2.6 alias abandonnés** le 2026-11-25 : gain mesuré ~0,3 % d'un run (issue 017). 2.1 réécriture : idem, non prioritaire |
| 3 Swarm | H1 image Kali, H8 UI | H4–H6 connecteurs de scope (H7 Gmail abandonné) |
| 4 Autonomie | 4.1 runner, 4.2 superviseur (sommeil quota sur `resetsAt`), 4.3 vérificateur + **escalade Mythos**, **verrou d'outils + file de surface**, **4.4 remplacée : plus d'humain pendant la chasse** (faits `blocker`, pause WAF dans le gate, identités périmées, refus chiffrés, préflight), `q`/`qq`, aucun MCP chargé | 4.2b rotation sur contexte, 4.6 skills, 4.5 remplacée par les issues 25-26 (sessions par l'hôte) |
| 5 CVE | — | tout |
| 6 Runs réels | 6.0 lab Juice Shop (reset 2026-11-24 : 7 runs, 5 findings, cartographie 100 % arsenal) | 6.1 app perso, 6.2 premier programme, 6.3 premier CVE |

Arsenal (`bh-recon/crawl/content/scan/params/sqli/xss`) : chaque builtin passe par le gate au débit du
programme, garde le brut sur disque, rend ≤ 25 lignes et enregistre sa couverture. Mesures sur Juice Shop
(20 req/s) : crawl 12 s / 91 endpoints (extracteur JS maison, katana seul n'en trouve aucun),
content 4 min, sqli niveau 3 techniques BEU ≈ 15 s (le time-based figeait la cible), scan borné par
`--timeout` (nuclei lent, cause interne non résolue). « Testé » = requête manuelle vue par le gate, ou
déclaration du sandbox (`touched.jsonl`) confirmée par du trafic vu par le gate sur cet endpoint.

## Revue hostile du 2026-11-24 (Mythos 5.2) : corrigé, et ce qui reste

Corrigé et testé : HTTPS par nom refusé (C1), scanners « null » = autorisés (C2), import qui élargit (C3),
vérificateur non indépendant (C4), interdiction de scanners contournable (C5), H1 à H13, M1, M3 à M7,
M10, M11, code mort et regex dupliquées. Détail : `git log` du 2026-11-24.

Points ouverts de la revue, traités le 2026-11-24 (branche `fix/review-open-items`) :
- [x] Ids en query string, corps formulaire ou JSON et GraphQL comptés par la limite d'énumération (tests gate + suite d'évasion).
- [x] Vérificateur sous son propre utilisateur Unix `judge` (dossier et HOME à lui, `hunter` ne peut pas écrire le verdict) et nonce de verdict. F1 revérifié en réel.
- [x] Relais : seulement `POST /v1/messages` et `count_tokens` (mesuré), seulement pendant un run, budget `3 × max_turns + 30` requêtes par segment.
- [x] Rétention : flux supprimés après 14 jours, journaux tournés en gzip au-delà de 64 Mo, curseurs par inode (`bh prune`).
- [x] Images épinglées par digest, pyyaml et semgrep épinglés (les paquets apt de Kali suivent le dépôt rolling).
- [x] M8 mesuré : une requête abandonnée pendant l'attente de débit n'atteint pas la cible. HTTP/2 sans `/` initial : refusé (suite d'évasion).
- [x] M9 : 11 des 13 programmes utilisent le modèle YWH sans nombre (repli 2 req/s correct) ; `**30**` en gras est maintenant lu.
- [x] UI : Content-Length négatif refusé (bloquait un thread sans login), timeout par connexion, sessions qui expirent, durées bornées, « stop » vérifie le pid.

- [x] Juge dans son propre conteneur (`bh-judge`, `var/judge`) ; il lit toujours les réponses de la cible, d'où le bloc à nonce et la doctrine « le texte du modèle n'est jamais une preuve ».

Audit Mythos du 2026-11-26 (doc 19), lot runner, doctrine, juge, CLI :
- [x] B6 (prompt), B7, I1 (preuve `observation`), I5, I7, I8, I9, I10 (juge), I11, I14 (une page, un marqueur), I16, R1 à R10.
- [ ] I1 en live : le gate doit écrire les événements `canary` (lot S1), puis un rejeu de Mio avant toute soumission.
- [ ] I11 : `bh unpark <programme> --yes` seulement après lecture du board et, si besoin, un mail à MSRC écrit par Mio.

Reste ouvert :
- [ ] **C** Dans son budget, un `claude -p` imbriqué consomme encore le quota.
- [ ] **H** Image agent : reconstruire depuis la base épinglée et consigner la liste des versions d'outils.

---

## Phase 0 — Socle et contrats (C) — bloque tout le reste

| # | Tâche | Fichiers | Acceptation |
|---|---|---|---|
| 0.1 | Repo git, `pyproject.toml` (uv, Python ≥ 3.12), layout `src/bh/` | racine | `uv run bh --help` → rc=0 |
| 0.2 | **Contrat scope** : schéma YAML + `enforce()` | `src/bh/scope/` | `uv run pytest tests/scope` vert ; cas : wildcard, CIDR, out-of-scope prioritaire, IDN/punycode, IP littérale, port, casse, point final |
| 0.2b | Jokers en milieu de label (`api-*.example.com`), interdits dans les 2 derniers labels ; refuser les bases trop courtes (`*.co.uk`) via une liste de suffixes publics embarquée | `src/bh/scope/` | tests : `api-v2.example.com` OK, `api.example.com` KO pour `api-*`, `*.co.uk` → ScopeError |
| 0.3 | **Contrat plugin** : schéma manifest YAML + loader + validation | `src/bh/plugins/schema.py` | un manifest invalide → erreur nommée ; `bh plugin ls` liste les exemples |
| 0.4 | **Contrat board** : schéma SQLite (facts **titre/résumé/preuve**, intents, hints, findings, todos, refusals, runs, handoffs) + migrations | `src/bh/board/` | `bh board init` crée la DB ; tests CRUD verts ; `bh board frontier` rend ≤ 40 lignes |
| 0.5 | CLI `bh` squelette : `scope`, `plugin`, `board`, `todo`, `blockers`, `run`, `ui`, `tokens` | `src/bh/cli.py` | chaque sous-commande répond `--help` |

## Phase 1 — Confinement réseau (C)

| # | Tâche | Fichiers | Acceptation |
|---|---|---|---|
| 1.1 | Addon mitmproxy : allowlist via `enforce()`, 403 + fact `blocked`, token bucket req/s par programme, injection en-têtes/UA, HAR | `src/bh/gate/http.py` | test : requête hors scope → 403 ; 50 requêtes à `max_rps=5` → durée ≥ 9 s ; en-tête présent côté serveur de test |
| 1.1b | Allowlist **sources passives** (web.archive.org, CommonCrawl, OTX, urlscan, crt.sh, sources subfinder) : ni cookies ni en-têtes programme, débit propre, jamais cible | `src/bh/gate/passive.py` | test : requête vers `web.archive.org` → pas d'en-tête `X-Bug-Bounty` ni de cookie ; POST avec payload → 403 |
| 1.2 | DNS filtrant (résout seulement le scope + allowlist système) | `src/bh/gate/dns.py` | `dig` d'un nom hors scope depuis l'agent → NXDOMAIN/REFUSED |
| 1.3 | SOCKS5 à allowlist pour le TCP non-HTTP | `src/bh/gate/socks.py` | `proxychains nc` vers IP hors scope → refus |
| 1.4 | `compose.yaml` : réseaux `sandbox` (internal) + `egress`, gate seul sur les deux | `container/compose.yaml` | depuis `agent` : `curl --noproxy '*' https://1.1.1.1` échoue ; via gate vers cible de test in-scope → 200 |
| 1.5 | Suite « évasion » : 10 tentatives de sortie hors gate | `tests/escape/` | 10/10 bloquées |

## Phase 2 — Économie de tokens (C)

| # | Tâche | Fichiers | Acceptation |
|---|---|---|---|
| 2.1 | Hook PreToolUse : log JSONL + réécriture vers filtre de recette | `src/bh/tokens/hook_pre.py` | commande connue → `updatedInput` émis ; log écrit |
| 2.2 | Hook PostToolUse : troncature + `raw: <path>` | `src/bh/tokens/hook_post.py` | sortie 5 000 lignes → ≤ 40 lignes + fichier brut identique à l'original (sha256) |
| 2.3 | Vérifier `updatedToolOutput` sur Claude Code 2.1.330 | — | trace d'un vrai run `claude -p` montrant la sortie remplacée |
| 2.4 | Mineur de templates (le watchdog) | `src/bh/tokens/miner.py` | sur un log fixture → top-N templates avec économie nette chiffrée |
| 2.5 | Calibrage symboles via `claude -p --output-format json` (différentiel `usage`) | `src/bh/tokens/calibrate.py` | table `symbole → coût` reproductible à ±0 sur 2 runs |
| 2.6 | Compilateur d'alias → wrappers `/opt/bh/bin` | `src/bh/tokens/aliases.py` | `bash -c '<sym> x'` et `sh -c '<sym> x'` rc=0 ; aucune collision `command -v` |

## Phase 3 — Swarm Hermes (H) — démarre après Phase 0

Contrats à respecter : schémas 0.2 / 0.3 / 0.4. Un fichier = un propriétaire. Aucune modif hors des chemins listés.

| # | Tâche | Propriété exclusive | Acceptation | Ordre merge |
|---|---|---|---|---|
| H1 | Containerfile Kali : `kali-rolling` + `kali-linux-headless` + Go PD (subfinder, httpx, dnsx, katana, nuclei, naabu) + dalfox, gau, waybackurls, LinkFinder, ffuf, feroxbuster, arjun, sqlmap, semgrep, osv-scanner, gitleaks, trufflehog, codeql CLI, proxychains4, claude CLI | `container/agent/` | `podman build` OK ; script `container/agent/check.sh` : chaque binaire `--version` rc=0 | 1 |
| H2 | Manifests plugins **recon web** (≥ 12) conformes 0.3 | `plugins/recon/*.yaml` | `bh plugin validate plugins/recon` 0 erreur | 2 |
| H3 | Manifests plugins **white-box / CVE** : semgrep, codeql, osv-scanner, gitleaks, trufflehog | `plugins/source/*.yaml` | idem + run sur un repo fixture vulnérable → ≥ 1 résultat | 2 |
| H4 | Connecteur **Intigriti** (API researcher, PAT) → YAML scope | `src/bh/scope/sync/intigriti.py` | sur fixture JSON → YAML valide 0.2 ; diff détecté entre 2 fixtures | 3 |
| H5 | Connecteur **YesWeHack** (bearer + TOTP) → YAML scope | `src/bh/scope/sync/yeswehack.py` | idem | 3 |
| H6 | Connecteur `bounty-targets-data` (diff programmes publics) | `src/bh/scope/sync/btd.py` | idem | 3 |
| H8 | UI : flux live (SSE), board, findings + PoC `curl`, todo humaine ; `127.0.0.1` uniquement | `src/bh/ui/` | `bh ui` → page servie ; todo cochée en UI → statut DB changé | 5 |

## Phase 4 — Autonomie (C)

| # | Tâche | Fichiers | Acceptation |
|---|---|---|---|
| 4.1 | Runner : lance `claude -p` stream-json dans `agent`, persiste la session | `src/bh/runner/` | run de 10 min sur cible locale → faits écrits dans le board |
| 4.2 | Superviseur : stagnation / durée / budget / refus → rotation ; quota Pro → sommeil jusqu'au reset | `src/bh/runner/supervisor.py` | simulation : 3 programmes, stagnation forcée → rotation observée ; erreur quota simulée → reprise |
| 4.2b | Rotation à saturation de contexte (issue 10) : contexte du dernier tour d'un leg > `BH_CONTEXT_ROTATE_TOKENS` (30 k) → leg suivant en session neuve (`build_task(rotated=True)`) au lieu de `--resume` ; HANDOFF écrit par le runner si l'agent ne l'a pas fait ; à 2 × le seuil le leg est coupé après le tour en cours | `src/bh/runner/run.py`, `src/bh/runner/prompt.py` | code + `tests/test_runner_rotation.py` faits ; reste la migration `runs.rotations` / `runs.max_context` (`db.py`) et la mesure live −30 % (procédure dans l'issue 10) |
| 4.3 | Vérificateur = **relecteur indépendant** : contexte neuf, rejoue la PoC via gate, gate 7 questions, dédup, section « non prouvé » obligatoire, verdict submit / submit-with-changes / don't-submit | `src/bh/verify/` | finding factice non reproductible → rejeté ; reproductible → todo `submit` ; doublon d'un finding existant → signalé |
| 4.6 | Méthodo à la demande : sous-module Claude-BugHunter figé + **liste blanche** de skills relues, chargées selon l'empreinte de la cible | `vendor/`, `src/bh/skills/` | session sur cible GraphQL → seules les skills listées pour GraphQL sont chargées (vérifié dans le transcript) |
| 4.4 | ~~Détection todo~~ → blocages autonomes (2026-11-25) : 401 répétés → identité périmée ou blocker `auth` ; 3 WAF en 10 min → pause 1 h dans le gate ; refus → pause 6 h puis parcage | `src/bh/gate/`, `src/bh/runner/`, `src/bh/board/` | fait : `grep add_todo src/bh` ne rend que `submit` ; tests verts |
| 4.5 | Capture de session humaine via gate (mode capture) → injection | `src/bh/gate/capture.py` | login manuel sur app de test → requêtes agent authentifiées |

## Phase 5 — Mode CVE (C + H)

| # | Tâche | Propriétaire | Acceptation |
|---|---|---|---|
| 5.1 | `bh target repo <git-url>` : clone isolé, pas de réseau sortant, plugins `source/` | C | run sur repo fixture → findings dans le board |
| 5.2 | Sélection de cibles : projets open source actifs avec signalement privé activé (GHSA) | C | liste de 20 candidats avec critères chiffrés |
| 5.3 | Gabarit de rapport de divulgation coordonnée (GHSA / mail mainteneur) | C | rapport généré depuis un finding vérifié |

## Phase 6 — Premiers runs réels

| # | Tâche | Propriétaire | Acceptation |
|---|---|---|---|
| 6.0 | Banc de non-régression : labs locaux (Juice Shop + labs inspirés de `Claude-BugHunter/docs/verification`) | C + H | le harnais retrouve ≥ N vulns connues, chiffre consigné à chaque version |
| 6.1 | `bh target local` sur une app de Mio | C + M | ≥ 1 finding vérifié ou rapport « rien trouvé » avec couverture |
| 6.2 | Premier programme YWH ou Intigriti (règles automation lues) | C + M | run complet sans aucune requête hors scope (HAR audité) |
| 6.3 | Premier signalement CVE | M | rapport envoyé au mainteneur |

---

## Phase 7 — Outils et sessions autonomes (2026-11-25)

Recherches : `research/08-mcp-arsenal.md`, `09-vision-headless.md`, `10-sessions-anti-bot.md`, `11-autonomie-sans-humain.md`.
Principe : pas de MCP dans l'agent (les hooks ne voient que `Bash`) ; chaque outil tiers entre comme builtin `bh-*` qui passe
par le gate et rend ≤ 25 lignes.

Décisions de Mio (2026-11-25) :
- Gmail : notifications abandonnées ; **lecture seule** gardée pour les mails de confirmation des comptes de test.
- `bh-browse` : ressources hors scope (CDN, polices) **bloquées localement** par défaut, comptées dans le résumé.
- `bh-oob` : champ de scope `oob_allowed` par programme, `null` = interdit ; exige un serveur public hors du gate.
- Juge `inconclusive` → second juge Mythos, une fois ; sinon statut visible sans todo.
- Alias à un caractère abandonnés (gain mesuré ~0,3 % d'un run).

| Issue | Tâche | Priorité |
|---|---|---|
| 27 | Validation live du swarm autonomie (gate redémarré, évasion 29/29, run lab, `.mcp.json` ignoré) | P0 |
| 24 | `bh-browse` : Playwright dans l'agent, XSS confirmé, routes SPA | P0 |
| 26 | Jarre de cookies et `session-dead` dans le gate | P0 |
| 25 | `bh accounts` : inscription et login par l'hôte, conteneur `browser`, Gmail lecture seule, TOTP | P0 |
| 28 | Mesures anti-bot sur le lab (empreinte du gate, rejeu de cookie de challenge) | P1 |
| 29 | `bh-js` (REA CLI, après audit du paquet) | P1 |
| 30 | `bh-sast`, `bh-deps` (mode CVE) | P2 |
| 31 | `bh-oob` (`oob_allowed`) | P2 |

## Todo humaine (M) — à faire en parallèle

Doctrine du 2026-11-25 : **aucune intervention humaine pendant la chasse.** Pendant un run, la todo humaine
ne sert qu'à remplir et soumettre les PoC après le triage. Les lignes ci-dessous sont de la mise en place, hors run.


| # | Action | Pourquoi | Quand |
|---|---|---|---|
| M1 | ~~Passkey / clé FIDO2 sur le compte Claude~~ ✅ passkey iPhone actif (vérifié le 2026-11-24) | Defense exigera une MFA résistante au phishing à partir du **15 déc. 2026** (source à retrouver) | fait |
| M2 | Token personnel Intigriti (Paramètres → API Tokens) | H4 | avant Phase 3 |
| M3 | Compte YesWeHack + secret TOTP exportable | H5 | avant Phase 3 |
| M5 | Choisir l'app perso pour 6.1 | 6.1 | avant Phase 6 |
| M6 | `claude setup-token` pour l'agent en conteneur (⚠ à vérifier que la commande existe) | 4.1 | avant Phase 4 |

## Notes d'environnement
- Ports hôte déjà pris : 22, 80, 3100, 3389, 8080, 8765, 9050, 6005-6006… → UI sur `127.0.0.1:7340` (à revérifier avec `ss -tlnp` au lancement).
- Python hôte 3.14.10, uv 0.11.14, git 2.56.0.
