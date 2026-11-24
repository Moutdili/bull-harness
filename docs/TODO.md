# bull-harness — TODO maître

Décisions figées (2026-11-22) : CVP **Defense** (individuel, Pro) · Podman rootless · YWH + Intigriti d'abord · objectif court terme : **premiers CVE** (divulgation coordonnée) → dossier Red Team plus tard.

Légende propriétaire : **C** = Claude (en direct, parties critiques) · **H** = Hermes (swarm) · **M** = Mio (humain).
Chaque tâche a un critère d'acceptation **binaire**. Une tâche n'est finie que si le critère passe en sortie d'outil réelle.

## État au 2026-11-24 (vérifié par tests ou run réel)

| Phase | Fait | Reste |
|---|---|---|
| 0 Socle | 0.1, 0.2 (scope + 80+ tests), 0.4 board (+ migrations, reset), 0.5 CLI | 0.2b jokers mi-label / PSL. 0.3 remplacé par les builtins `bh.agent.tools` (pas de manifests YAML) |
| 1 Confinement | 1.1 gate HTTP, 1.1b passifs (liste partagée `bh.agent.contract`), 1.4 réseaux (évasion testée) | 1.2 DNS, 1.3 SOCKS (le non-HTTP est coupé), 1.5 suite d'évasion, élargir les sources passives de subfinder |
| 2 Tokens | 2.2 troncature, 2.3 `updatedToolOutput` vérifié, base par tour −62 % (`--tools Bash,Read`, sans slash commands), sessions neuves par défaut | 2.1 réécriture, 2.4 mineur, 2.5 calibrage, 2.6 alias |
| 3 Swarm | H1 image Kali, H8 UI | H4–H6 connecteurs de scope, H7 Gmail |
| 4 Autonomie | 4.1 runner (stderr fichier, kill propre), 4.2 superviseur (progression réelle), 4.4 todos auth/waf/identity, **verrou d'outils + file de surface** | 4.2b rotation sur contexte, 4.3 vérificateur, 4.5 capture de session, 4.6 skills |
| 5 CVE | — | tout |
| 6 Runs réels | 6.0 lab Juice Shop (13 runs, 11 findings connus) | 6.1 app perso, 6.2 premier programme, 6.3 premier CVE |

Arsenal (`bh-recon/crawl/content/scan/params/sqli/xss`) : chaque builtin passe par le gate au débit du
programme, garde le brut sur disque, rend ≤ 25 lignes et enregistre sa couverture. Mesures sur Juice Shop
(20 req/s) : crawl 12 s / 91 endpoints (extracteur JS maison, katana seul n'en trouve aucun),
content 4 min, sqli niveau 3 ≈ 3 min, scan borné par `--timeout` (nuclei lent, cause interne non résolue).

---

## Phase 0 — Socle et contrats (C) — bloque tout le reste

| # | Tâche | Fichiers | Acceptation |
|---|---|---|---|
| 0.1 | Repo git, `pyproject.toml` (uv, Python ≥ 3.12), layout `src/bh/` | racine | `uv run bh --help` → rc=0 |
| 0.2 | **Contrat scope** : schéma YAML + `enforce()` | `src/bh/scope/` | `uv run pytest tests/scope` vert ; cas : wildcard, CIDR, out-of-scope prioritaire, IDN/punycode, IP littérale, port, casse, point final |
| 0.2b | Jokers en milieu de label (`api-*.example.com`), interdits dans les 2 derniers labels ; refuser les bases trop courtes (`*.co.uk`) via une liste de suffixes publics embarquée | `src/bh/scope/` | tests : `api-v2.example.com` OK, `api.example.com` KO pour `api-*`, `*.co.uk` → ScopeError |
| 0.3 | **Contrat plugin** : schéma manifest YAML + loader + validation | `src/bh/plugins/schema.py` | un manifest invalide → erreur nommée ; `bh plugin ls` liste les exemples |
| 0.4 | **Contrat board** : schéma SQLite (facts **titre/résumé/preuve**, intents, hints, findings, todos, refusals, runs, handoffs) + migrations | `src/bh/board/` | `bh board init` crée la DB ; tests CRUD verts ; `bh board frontier` rend ≤ 40 lignes |
| 0.5 | CLI `bh` squelette : `scope`, `plugin`, `board`, `todo`, `run`, `ui`, `alias` | `src/bh/cli.py` | chaque sous-commande répond `--help` |

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
| H7 | Notifier Gmail (Pub/Sub **pull**, renouvellement `watch` 6 j) → `bh scope sync` | `src/bh/notify/gmail.py` | mail de test → appel `sync` loggé | 4 |
| H8 | UI : flux live (SSE), board, findings + PoC `curl`, todo humaine ; `127.0.0.1` uniquement | `src/bh/ui/` | `bh ui` → page servie ; todo cochée en UI → statut DB changé | 5 |

## Phase 4 — Autonomie (C)

| # | Tâche | Fichiers | Acceptation |
|---|---|---|---|
| 4.1 | Runner : lance `claude -p` stream-json dans `agent`, persiste la session | `src/bh/runner/` | run de 10 min sur cible locale → faits écrits dans le board |
| 4.2 | Superviseur : stagnation / durée / budget / refus → rotation ; quota Pro → sommeil jusqu'au reset | `src/bh/runner/supervisor.py` | simulation : 3 programmes, stagnation forcée → rotation observée ; erreur quota simulée → reprise |
| 4.2b | Rotation à saturation de contexte : au-delà du seuil, l'agent écrit un `handoff` (playbook) puis session neuve | `src/bh/runner/supervisor.py` | simulation seuil franchi → handoff écrit, nouvelle session le lit |
| 4.3 | Vérificateur = **relecteur indépendant** : contexte neuf, rejoue la PoC via gate, gate 7 questions, dédup, section « non prouvé » obligatoire, verdict submit / submit-with-changes / don't-submit | `src/bh/verify/` | finding factice non reproductible → rejeté ; reproductible → todo `submit` ; doublon d'un finding existant → signalé |
| 4.6 | Méthodo à la demande : sous-module Claude-BugHunter figé + **liste blanche** de skills relues, chargées selon l'empreinte de la cible | `vendor/`, `src/bh/skills/` | session sur cible GraphQL → seules les skills listées pour GraphQL sont chargées (vérifié dans le transcript) |
| 4.4 | Détection todo : 401/403 répétés → `auth` ; challenge WAF → `waf` ; refus → `refusal` | `src/bh/gate/`, `src/bh/runner/` | fixtures → todos créées |
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

## Todo humaine (M) — à faire en parallèle

| # | Action | Pourquoi | Quand |
|---|---|---|---|
| M1 | **Passkey / clé FIDO2 sur le compte Claude** | Defense exigera une MFA résistante au phishing à partir du **15 déc. 2026** | avant le 15/12 |
| M2 | Token personnel Intigriti (Paramètres → API Tokens) | H4 | avant Phase 3 |
| M3 | Compte YesWeHack + secret TOTP exportable | H5 | avant Phase 3 |
| M4 | Projet Google Cloud + Pub/Sub + OAuth Gmail | H7 | avant Phase 3 |
| M5 | Choisir l'app perso pour 6.1 | 6.1 | avant Phase 6 |
| M6 | `claude setup-token` pour l'agent en conteneur (⚠ à vérifier que la commande existe) | 4.1 | avant Phase 4 |

## Notes d'environnement
- Ports hôte déjà pris : 22, 80, 3100, 3389, 8080, 8765, 9050, 6005-6006… → UI sur `127.0.0.1:7340` (à revérifier avec `ss -tlnp` au lancement).
- Python hôte 3.14.10, uv 0.11.14, git 2.56.0.
