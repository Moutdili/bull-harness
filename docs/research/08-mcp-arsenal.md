# 08 — Arsenal MCP et outils agentiques (web + RE)

Veille du **2026-11-25**. Complète `03-repos-et-outils.md` (HexStrike, CyberStrikeAI, Strix… y sont déjà).
Les chiffres ★ / dernier push / licence ont été lus via `gh api repos/<owner>/<repo>` le 2026-11-25.
Légende : ✅ vérifié (source citée ou commande rejouable), ⚠ supposé (méthode de vérification en §5).

---

## 1. Résumé

- **Faille actuelle (✅, à corriger avant tout MCP).** `claude -p` charge sans demander un `.mcp.json` de projet. Le cwd de l'agent est `/work/<prog>`, inscriptible par `hunter`. `run.py` efface `CLAUDE.md` et `.claude`, pas `.mcp.json`, et ne passe ni `--strict-mcp-config` ni `--disallowedTools "mcp__*"`. `--tools Bash,Read` ne filtre **pas** les outils MCP.
- **Conséquence.** Un segment peut planter un serveur MCP pour le segment suivant. Ses appels échappent au verrou (`matcher: "Bash"`), aux règles de programme et à la troncature. Le scope réseau tient quand même : le réseau `sandbox` n'a pas de route, tout passe par le gate.
- **Doctrine retenue.** Pas de MCP direct dans l'agent tant que les hooks ne couvrent pas `mcp__.*`. On préfère un wrapper CLI en builtin `bh-*` (≤ 25 lignes, brut sur disque). Le MCP n'apporte rien de plus quand l'outil a une CLI équivalente.
- **Top 5.** (1) navigateur Playwright via `bh-browse`, (2) REA CLI via `bh-js` (bundles JS, source maps), (3) Semgrep local via `bh-sast`, (4) OSV-Scanner hors ligne via `bh-deps`, (5) interactsh auto-hébergé via `bh-oob` (OOB).
- **Écartés pour l'agent.** Burp MCP (GUI, licence Pro pour Collaborator), Caido MCP (instance + compte cloud, doublon du gate + `q`), HexStrike / Kali MCP (150 schémas, doublon des builtins), MCP de plateformes (secrets hors agent).

---

## 2. Inventaire

Colonnes « Cadre » : **H** = tourne headless en conteneur ; **P** = trafic forçable via `gate:8080` ; **S** = besoin d'un secret ou d'une licence ; **T** = transport.
« Tokens » : taille des schémas exposés et verbosité. Tout MCP tiers exécute du code avec les droits de `hunter`.

### 2.1 Proxys d'interception

| Outil | Ce qu'il fait | Maturité ✅ | Cadre | Supply chain / tokens | Doublon | Verdict |
|---|---|---|---|---|---|---|
| **Burp MCP** `PortSwigger/mcp-server` | Extension Burp. Envoi HTTP/1.1 et HTTP/2, historique proxy (regex, paginé), Repeater, Intruder, encodeurs, édition de la config, Collaborator. | 21 ★, push 2026-11-05, GPL-3.0, Kotlin, officiel PortSwigger | H ⚠ (extension GUI ; headless Burp = `-Djava.awt.headless=true`, non documenté pour l'extension). P ✅ (upstream proxy Burp). S : licence Pro pour `GetScannerIssues` et Collaborator ✅ (`Tools.kt` l.252 : bloc `if edition == PROFESSIONAL`). T : streamable HTTP `127.0.0.1:9876/mcp`, SSE `/`, stdio via `mcp-proxy-all.jar`. | Jar à builder soi-même. ~25 outils. Outils d'édition de config activables (risque : l'agent change l'upstream proxy de Burp). | `q`, `qq`, gate | ❌ agent. Collaborator seul intérêt → interactsh fait pareil sans licence. |
| **Caido MCP** `c0tton-fluff/caido-mcp-server` | 76 outils : historique HTTPQL, replay, batch, race (`caido_race_pipeline`), tamper, findings, websockets. CLI `caido-cli` (`send`, `raw`, `batch`, `history`). | 159 ★, push 2026-11-24, MIT, Go, **non officiel** (doc Caido le dit) | H : `caido/caido` en Docker ✅. Instance enregistrée via le Dashboard cloud (clé Team ou manuel) ✅. Accès Internet de l'instance vers le cloud Caido ⚠. S : `CAIDO_ACCESS_TOKEN` (~7 j) ou OAuth device flow ✅. T : stdio. | Corps tronqués à 2 KB par défaut, `CAIDO_MCP_TOOLSETS` / `CAIDO_MCP_COMPACT` / `CAIDO_MCP_READ_ONLY` ✅. 76 schémas = lourd sans filtrage. | gate + `q`/`qq` | ❌ agent. Idée à reprendre : `race_pipeline` → futur `q --race`. |
| Caido Skills (officiel) | SDK client Caido + skill pour agents. | Annonce 2026-03-06 | Même instance + compte. | — | idem | ❌ |
| **ZAP MCP add-on** (officiel OWASP) | Add-on dans le process ZAP. Spider, scans, alertes. Peut aussi importer un serveur MCP pour le scanner. | `zaproxy/zap-extensions` 956 ★, push 2026-11-24, Apache-2.0 | H ⚠ (ZAP daemon existe ; add-on MCP en daemon non documenté). P ⚠ (proxy amont ZAP). S : clé API optionnelle, envoyée en HTTP clair ✅. T : HTTP `localhost:8282`, CORS `*` ✅. | Liste d'outils sur une page séparée, non lue. | `bh-scan`, `bh-crawl` | ❌ agent. Intérêt futur : tester des serveurs MCP **cibles** (surface « agents IA » de `05-carriere`). |
| `dtkmn/mcp-zap-server` | ZAP via Spring Boot. | 71 ★, push 2026-11-24, Apache-2.0 | idem | Tiers | idem | ❌ |
| **mitmproxy-mcp** `snapspecter/mitmproxy-mcp` | Démarre un mitmproxy local, `set_scope`, lecture et rejeu des flux. 25 outils (Glama). | 137 ★, push 2026-11-06, MIT, Python | H ✅. P : il **est** un proxy, il faudrait le chaîner au gate. T : stdio. | Tiers ; lance un second proxy dans l'agent. | gate (déjà mitmproxy) | ❌ doublon direct du gate. |

### 2.2 Navigateurs (inventaire seul ; la vision est creusée par un autre agent)

| Outil | Ce qu'il fait | Maturité ✅ | Cadre | Supply chain / tokens | Doublon | Verdict |
|---|---|---|---|---|---|---|
| **Playwright MCP** `microsoft/playwright-mcp` | 25 outils cœur (`browser_navigate`, `browser_snapshot`, `browser_network_requests`, `browser_evaluate`, `browser_run_code_unsafe`…). Groupes optionnels `--caps` : network, storage, devtools, vision, pdf, testing. | 40 106 ★, push 2026-11-18, Apache-2.0 | H ✅ `--headless`. P ✅ `--proxy-server`, `--proxy-bypass`, `--ignore-https-errors`. Filtrage `--allowed-origins` / `--blocked-origins` ✅. T : stdio ou HTTP `--port`. | Éditeur Microsoft. Snapshots d'accessibilité verbeux. Le README conseille « CLI+SKILLS » aux agents de code pour les tokens ✅. | aucun (pas de navigateur aujourd'hui) | ✅ **Top 1**, en wrapper. |
| **chrome-devtools-mcp** `ChromeDevTools/chrome-devtools-mcp` | DevTools via CDP : réseau, console, perf, traces. | 59 206 ★, push 2026-11-24, Apache-2.0 | H ✅ `--headless`, `--isolated`, `--executablePath`, `--slim`. P ⚠ (option proxy non trouvée dans le README ; passer par les args Chrome à vérifier). Télémétrie par défaut : couper avec `--no-usage-statistics` et `--no-performance-crux` ✅ (sinon des URL de trace partent vers CrUX). T : stdio. | Officiel Google. | Playwright | ⚠ alternative si Playwright bloque. |
| Autres (lister seulement) | Browserbase / Stagehand, Browserless, `scrapling` (présent sur l'hôte de Mio) | — | Services cloud ou stealth : hors cadre (sortie non contrôlée). | — | — | ❌ |

### 2.3 Rétro-ingénierie

| Outil | Ce qu'il fait | Maturité ✅ | Cadre | Supply chain / tokens | Doublon | Verdict |
|---|---|---|---|---|---|---|
| **REA** `morluto/rea`, npm `rea-agents` | MCP + CLI. Natif (Ghidra/IDA/Hopper/Kuna, BYO), .NET, APK, firmware, et web : `analyze_web_bundle`, `recover_javascript_sources`, `trace_web_source_location`, `trace_web_module_imports`, `compare_bundles`, `export_web_scripts`. Le flux CLI et le flux MCP sont partagés (`rea trace-web-source-location … --json`) ✅. | API GitHub : **477 056 ★, 116 134 forks**, créé 2026-04-14, push 2026-11-24, MIT, **un seul mainteneur** npm (`morluto`), `rea-agents` 6.10.1 du 2026-11-20 | H ✅ (analyse statique locale, « fetches no URL » pour le traçage de source map). P : sans objet en statique ; capture navigateur ⚠. S : aucun pour JS/.NET ; Ghidra/IDA à fournir pour le natif. T : stdio. | **229 outils** MCP (compté dans la session hôte de Mio) : inutilisable en direct. Chiffres GitHub anormaux pour 7 mois d'existence → risque supply chain élevé, épingler la version et auditer. | extracteur JS de `bh-crawl` (partiel) | ✅ **Top 2**, CLI en wrapper. |
| `LaurieWired/GhidraMCP` | Plugin Ghidra + serveur MCP : décompilation, renommage, xrefs. | 12 028 ★, push 2026-10-10, Apache-2.0 | Plugin GUI (CodeBrowser) ⚠ headless. T : HTTP local + bridge Python. | Tiers. | REA (provider Ghidra) | ❌ web ; hôte de Mio seulement. |
| `clearbluejar/pyghidra-mcp` | Ghidra en ligne de commande (pyghidra), sans GUI. | 469 ★, push 2026-11-24, Apache-2.0 | H ✅ (description « Command-Line Ghidra MCP »). | Ghidra lourd (JDK). | REA | ⚠ seulement si un programme a un binaire client dans le scope. |
| `mrexodia/ida-pro-mcp` | IDA Pro via plugin ou idalib. | 13 563 ★, push 2026-11-12, MIT | S : licence IDA Pro. | — | REA | ❌ licence. |
| `radareorg/radare2-mcp` (`r2mcp`) | radare2 en MCP. Mode lecture seule, sandbox r2, restriction d'outils, HTTP `-H` avec bearer `-a` ✅. | 367 ★, push 2026-11-24, MIT, officiel radareorg | H ✅. Réseau : aucun. radare2 6.0.4 **déjà installé** dans l'agent ✅. T : stdio ou HTTP. | Projet officiel, outils configurables finement. | `r2 -q -c` en Bash | ⚠ si binaire natif ; sinon `r2` en Bash suffit. |
| `zinja-coder/jadx-ai-mcp` + `jadx-mcp-server` | Plugin JADX GUI + serveur MCP. | 3 032 ★ / 855 ★, push 2026-10-19, Apache-2.0 | Plugin GUI ⚠ headless. | Tiers. | REA (`inspect_android_*`), `jadx` CLI | ❌ pour le web. |
| Frida MCP (`dnakov/frida-mcp` 472 ★ push 2025-05-12 ; `yfe404/frida-mcp` 29 ★ sans licence) | Instrumentation dynamique. | Fragmenté, pas de projet de référence | Besoin d'un appareil/émulateur. | Tiers, abandonnés ou sans licence. | REA (`instrument_with_frida`) | ❌ |
| `president-xd/revula` | Fourre-tout RE (Frida, r2, Capstone, jadx). | 88 ★, push 2026-08-16, GPL-3.0 | Docker. | Tiers, large. | REA | ❌ |
| JS hors MCP : `denandz/sourcemapper` (1 475 ★, push 2026-07-24, BSD-3), `BishopFox/jsluice` (1 979 ★, push 2024-05-22, MIT), `xnl-h4ck3r/xnLinkFinder` (1 601 ★, sans licence), `GerbenJavado/LinkFinder` (4 479 ★, push 2024-04) | Extraction d'URL, secrets, source maps. | — | H ✅, binaires simples. | jsluice et LinkFinder figés depuis 2024. | `bh-crawl` | ⚠ sourcemapper en repli si REA est rejeté. |

### 2.4 Offensif web, recon, plateformes

| Outil | Ce qu'il fait | Maturité ✅ | Cadre | Supply chain / tokens | Doublon | Verdict |
|---|---|---|---|---|---|---|
| ProjectDiscovery MCP officiel | **Aucun trouvé** (recherche GitHub `org:projectdiscovery mcp` vide). | — | — | — | — | — |
| `intelligent-ears/pd-tools-mcp` ; `addcontent/nuclei-mcp` | Wrappers nuclei/httpx/katana. | 8 ★ (push 2025-12) ; 51 ★ (push 2025-08) | Binaires PD requis. | Tiers, peu maintenus. | `bh-recon`, `bh-scan` | ❌ |
| HexStrike AI | ~150 outils (voir 03). | 13 878 ★, push 2026-08-03, MIT | Kali v6.0. | 150 schémas. | tous les builtins | ❌ (déjà tranché en 06). |
| `mcp-kali-server` (Kali, amont `Wh0am123/MCP-Kali-Server`) | API Flask qui exécute des commandes terminal + bridge MCP. | 883 ★, push 2026-03-17, MIT ; paquet Kali `0.0~git20260317`, dépend de `sudo` ✅ | Port 5000. | Exécution de commande arbitraire sans hook. | Bash | ❌ contourne le verrou par construction. |
| `metasploitmcp` (Kali, amont `GH05TCREW/MetasploitMCP`) | Metasploit en MCP. | paquet Kali `0.0~git20260205` | stdio/HTTP. | — | hors périmètre (exploit dev = Red Team, pas Defense) | ❌ |
| `DMontgomery40/pentest-mcp` | Pentest généraliste. | 151 ★, push 2026-10-30, AGPL-3.0 | — | — | builtins | ❌ |
| Nmap MCP (`PhialsBasement/nmap-mcp-server` 49 ★), SQLMap MCP (`mohdhaji87/SQLMap-MCP` 7 ★) | Wrappers. | Petits, souvent sans licence | — | — | `bh-sqli`, nmap | ❌ |
| interactsh MCP (`rek7/interactsh-mcp` 3 ★…) | OOB. | Jouets. | — | — | — | ❌ ; utiliser `projectdiscovery/interactsh` (4 660 ★, push 2026-11-21, MIT) directement. |
| **HackerOne MCP officiel** | Rapports, programmes, assets, bounties. | GA annoncée dans le changelog H1 de juillet 2026 ✅ | S : compte H1. | Secret de plateforme. | sync scope côté hôte | ❌ agent ; ⚠ hôte quand H1 arrive. |
| `PatrikFehrenbach/h1-brain` | H1 + base de connaissance. | 362 ★, push 2026-11-20, MIT | S : token H1. | — | — | ❌ agent. |
| YesWeHack / Intigriti MCP | **Aucun officiel trouvé.** Communautaires : `Miro-sh/yeswehack-mcp` 3 ★, `alpernae/intigriti-mcp` 4 ★. | — | S : bearer + TOTP (YWH), token (Intigriti). | Secrets de plateforme dans un code inconnu. | `bh.scope` sync | ❌ |
| Agents bug bounty Claude Code : `awarexone/Agentic-Bug-Hunter` (6 054 ★, push 2026-11-12, MIT), `H-mmer/pentest-agents` (1 347 ★, sans licence), `transilienceai/communitytools` (636 ★, MIT), `h4ckologic/bughunter-ai` (104 ★, Burp MCP) | Skills, agents, MCP de plateformes et de writeups. | — | — | Skills = texte injecté dans le contexte : à lire, pas à monter. | prompt système / doctrine | ⚠ veille : comparer leurs checklists à la doctrine. |

### 2.5 Mode CVE white-box

| Outil | Ce qu'il fait | Maturité ✅ | Cadre | Supply chain / tokens | Doublon | Verdict |
|---|---|---|---|---|---|---|
| **Semgrep** (`semgrep mcp`) | Serveur MCP intégré au binaire ; l'ancien dépôt `semgrep/mcp` est **archivé**. `semgrep mcp --transport stdio|streamable-http` ✅ (vu dans l'agent, semgrep 1.186.0 déjà installé). | Blog Semgrep 2026-11-12 : bêta ; outils plateforme = `SEMGREP_APP_TOKEN`. | H ✅. Réseau : `--config auto` et les métriques appellent semgrep.dev → bloqué par le gate. Règles à embarquer au build, `--metrics=off`. | Binaire déjà présent, pas de nouveau code. | aucun | ✅ **Top 3**, CLI en wrapper. |
| **OSV-Scanner** `google/osv-scanner` | SCA. Sous-commande `experimental-mcp` (stdio ou `--sse`), outils `scan_vulnerable_dependencies`, `get_vulnerability_details`, `ignore_vulnerability` ✅ (`cmd/osv-scanner/mcp/command.go`). | 11 615 ★, push 2026-11-24, Apache-2.0, Google | H ✅. Réseau : api.osv.dev, ou base hors ligne ⚠. | Éditeur Google. | aucun | ✅ **Top 4**, CLI en wrapper. |
| `StacklokLabs/osv-mcp` | Requête OSV. | 45 ★, Apache-2.0 | Réseau OSV. | — | osv-scanner | ❌ |
| `microsoft/github-advisory-mcp` | GHSA depuis un clone local de la base d'avis. | 9 ★, push 2026-11-13, MIT | Hors ligne après clone ✅ (`git pull` au démarrage, à couper). | Petit, Microsoft. | — | ⚠ côté hôte, pour dédupliquer une CVE avant soumission. |
| `github/github-mcp-server` | API GitHub, dont scan de dépendances (preview 2026-05) ✅. | 34 724 ★, MIT | S : token GitHub. Deux CVE 2026 référencées (CVE-2026-47427, CVE-2026-48529). | Secret + surface. | `gh` sur l'hôte | ❌ agent. |
| CodeQL : `advanced-security/codeql-development-mcp-server` (39 ★, push 2026-11-24), `JordyZomer/codeql-mcp` (148 ★, push 2025-03, sans licence) | Écriture de requêtes CodeQL ; wrapper du query server. | — | Licence CodeQL : usage gratuit limité aux dépôts open source ⚠. Base CodeQL à construire (lourd). | — | Semgrep | ⚠ plus tard, cibles open source seulement. |

---

## 3. Top 5 à brancher (dans l'ordre)

**Prérequis 0 — durcir le chargement MCP (bloquant, avant tout le reste).**
- Passer `--strict-mcp-config` et `--disallowedTools "mcp__*"` à chaque `claude -p` ✅ (CLI reference).
- Effacer `.mcp.json` dans `_WORK_SCRIPT` comme `CLAUDE.md`.
- Ajouter `mcp__.*` aux matchers PreToolUse et PostToolUse ✅ (hooks : `mcp__<server>__.*`, `.*` obligatoire). Par défaut : `deny` pour tout outil MCP non listé.
- Pourquoi : le verrou, les règles de programme (scanners interdits, vérificateur sans outils) et la troncature ne regardent que `Bash`.

**1. Navigateur Playwright → `bh-browse` (wrapper).**
- Justification : aucun builtin ne rend une SPA, ne suit un flux d'auth JS ni ne confirme un XSS DOM. C'est le trou le plus large de l'arsenal web.
- Intégration : Playwright + Chromium installés au build. Lancement `--headless --proxy-server http://gate:8080`, CA du gate installée (préférer à `--ignore-https-errors`). L'identité passe par l'en-tête `X-BH-Identity` en `extraHTTPHeaders`.
- Sortie : titre, URL finale, requêtes XHR vues (méthode + chemin), erreurs console, ≤ 25 lignes. Snapshot complet et HAR dans `raw/`. Les endpoints vont dans `endpoints.jsonl`.
- Pourquoi pas le MCP : 25 schémas + snapshots verbeux, et le README lui-même oriente les agents de code vers la CLI. MCP seulement si le wrapper ne suffit pas pour des parcours multi-étapes (alors `--caps` minimal, `--allowed-origins` = scope).

**2. REA CLI → `bh-js` (wrapper).**
- Justification : les source maps et les bundles donnent routes cachées, rôles, flags et clés. `bh-crawl` extrait des chemins ; REA reconstruit les sources et trace les imports.
- Intégration : `npm install -g rea-agents@<version épinglée>` au build. Jamais `npx …@latest` (pas d'Internet, et refus de la mise à jour silencieuse). Analyse sur les scripts déjà rapatriés par `bh-crawl` dans `raw/`.
- Sortie : nombre de sources récupérées, nouveaux chemins (absents de `endpoints.jsonl`), indices de secrets. Le JSON complet reste sur disque (peut peser 100 Mo).
- Pourquoi pas le MCP : 229 outils. Risque supply chain à traiter : audit du paquet et de ses dépendances avant l'épinglage.

**3. Semgrep local → `bh-sast` (wrapper).**
- Justification : mode CVE white-box. Le binaire est déjà dans l'image, aucun nouveau code tiers.
- Intégration : règles copiées au build dans `/opt/bh/semgrep-rules`, `--metrics=off`, `--config` local uniquement. Cible : sources open source clonées par l'hôte et montées en lecture seule.
- Sortie : findings groupés par règle et par sévérité, ≤ 25 lignes ; SARIF dans `raw/`.
- Pourquoi pas `semgrep mcp` : il n'apporte que l'accès plateforme (token) ; la CLI suffit.

**4. OSV-Scanner hors ligne → `bh-deps` (wrapper).**
- Justification : CVE connues dans les lockfiles des cibles open source, et confirmation qu'une vuln trouvée n'est pas déjà publiée.
- Intégration : binaire épinglé au build. Base OSV hors ligne téléchargée par l'hôte (⚠ options exactes à vérifier), montée en lecture seule. Sinon `api.osv.dev` dans l'allowlist passive du gate.
- Sortie : paquet, version, ID OSV/GHSA, version corrigée, ≤ 25 lignes.

**5. interactsh auto-hébergé → `bh-oob` (wrapper).**
- Justification : SSRF, XXE, injection aveugle. Sans OOB, ces classes restent « supposées » et le juge les rejette.
- Intégration : serveur interactsh hors agent (hôte ou VPS de Mio), domaine dédié. Le client de l'agent poll ce serveur via une entrée d'allowlist **système** du gate (pas de cible). Les serveurs publics `oast.*` sont exclus : données de cible chez un tiers.
- Sortie : payload généré, puis interactions reçues (type, horodatage, IP source), ≤ 25 lignes.
- Décision de Mio requise : certains programmes interdisent les callbacks externes. Le gate doit lire une règle `oob_allowed` du scope.

Non retenus pour l'instant : r2mcp (utile seulement si un binaire natif entre dans le scope ; `r2` est déjà là), GHSA MCP (côté hôte, au triage), HackerOne MCP (côté hôte, quand H1 arrive).

---

## 4. Plan d'intégration (swarm Hermes)

Une tâche = un propriétaire = des fichiers exclusifs. Ordre de merge : T1 → T2 → T3 → (T4, T5, T6, T7 en parallèle) → T8.

| # | Fichiers (propriété exclusive) | Travail | Critère d'acceptation binaire |
|---|---|---|---|
| T1 | `src/bh/runner/run.py`, `tests/test_runner_mcp.py` (nouveau) | Ajouter `--strict-mcp-config`, `--disallowedTools "mcp__*"` (retiré seulement si `BH_MCP_CONFIG` est fourni), et `rm -f "$1/.mcp.json" "$2/.mcp.json"` dans `_WORK_SCRIPT`. | `pytest tests/test_runner_mcp.py` vert : la commande construite contient les deux options, le script efface `.mcp.json`. |
| T2 | `tests/escape/test_mcp_plant.py` (nouveau) | Test d'évasion live : planter un `.mcp.json` (serveur stdio factice) dans `/work/<prog>`, lancer un segment. | L'événement `system/init` du stream-json ne liste aucun serveur MCP ni outil `mcp__*` (⚠ nom exact du champ à confirmer). Sans T1, le même test échoue. |
| T3 | `container/agent/hooks/settings.json`, `src/bh/agent/hooks.py`, `src/bh/agent/contract.py`, `tests/agent/test_hooks.py` | Matchers `mcp__.*` en Pre et Post. Pre : `deny` si l'outil n'est pas dans une allowlist ; sinon extraire les URL de `tool_input` et appliquer `lock_decision` et `rules_decision`. Post : troncature via `updatedMCPToolOutput` (pas de validation de schéma côté MCP ✅). | Tests unitaires verts : un `tool_name` `mcp__x__y` non listé → `deny` ; une URL non couverte → message `[bh-lock]` ; une sortie de 200 lignes → tête + queue + chemin `raw/`. |
| T4 | `container/agent/Containerfile`, `container/agent/packages.txt` | Seul propriétaire de l'image : Chromium + Playwright épinglés, `rea-agents` épinglé, osv-scanner épinglé, client interactsh, règles Semgrep copiées. CA du gate dans le magasin système et NSS. | `container/agent/check.sh` vert et `playwright --version`, `rea --version`, `osv-scanner --version`, `interactsh-client -version` répondent dans l'agent ; aucune commande ne fait de requête réseau au premier lancement (log du gate vide). |
| T5 | `src/bh/agent/browse.py` (nouveau), `tests/agent/test_browse.py` | Builtin `bh-browse <url> [--as id]`. | Sur `bh-lab-juiceshop` : sortie ≤ 25 lignes, XHR `/rest/…` listées, HAR dans `raw/`, nouveaux endpoints dans `endpoints.jsonl` ; une URL hors scope → refus du gate visible dans la sortie. |
| T6 | `src/bh/agent/js.py` (nouveau), `tests/agent/test_js.py` | Builtin `bh-js <origin>` sur les scripts de `raw/`. | Sur Juice Shop : ≥ 1 chemin absent de la sortie `bh-crawl` ou « 0 nouveau » explicite ; ≤ 25 lignes ; aucun flux réseau émis par `rea` (log du gate). |
| T7 | `src/bh/agent/sast.py` (nouveau), `tests/agent/test_sast.py` | Builtins `bh-sast <dir>` et `bh-deps <dir>`. | Sur une fixture vulnérable connue : ≥ 1 finding Semgrep et ≥ 1 ID OSV ; ≤ 25 lignes ; zéro requête vers semgrep.dev (log du gate). |
| T8 | `src/bh/agent/main.py`, `src/bh/agent/tools.py`, `src/bh/runner/prompt.py`, `docs/architecture.md` | Enregistrer les builtins (liens `bh-*`), les ajouter au verrou de couverture et à la doctrine. `bh-oob` suit après la décision de Mio sur `oob_allowed`. | `bh-agent --help` liste les nouveaux builtins ; `pytest` complet vert ; un run sur Juice Shop appelle au moins une fois `bh-browse` et `bh-js` (métrique `runs.arsenal_calls`). |

---

## 5. Incertitudes

| Supposé | Comment le vérifier |
|---|---|
| PreToolUse se déclenche pour un outil MCP en `bypassPermissions` + `-p`. La doc dit « before every tool call, whether or not it needs permission », sans test MCP explicite. | T2/T3 : serveur MCP factice, hook qui écrit un fichier, puis `claude -p --debug='hooks,mcp'`. |
| Le `.mcp.json` du cwd `/work/<prog>` est bien chargé aujourd'hui (doc ✅, pas rejoué chez nous). | Test T2 sans le correctif T1. |
| Un serveur stdio hérite de `HTTP(S)_PROXY`. Node n'honore pas ces variables sans `NODE_USE_ENV_PROXY`. Effet : échec fermé (pas de route), pas fuite. | Lancer un serveur Node factice qui fait un `fetch` ; lire le log du gate. |
| Le relais `reverse@8081` transmet les champs `defer_loading` / `tool_reference` de la recherche d'outils (doc : activée par défaut derrière une passerelle depuis v2.1.304). | Un run avec un MCP de test ; vérifier l'absence d'erreur 400 dans `err.log`. |
| Chiffres REA (477 k ★, 116 k forks en 7 mois, un seul mainteneur) : anormaux, peut-être gonflés. | `gh api repos/morluto/rea/stargazers` échantillonné ; `npm audit` et lecture du paquet avant l'épinglage. |
| Caido headless : l'instance doit-elle joindre le cloud Caido pour démarrer ? | Lancer `caido/caido` sur un réseau interne et lire ses logs. Non prioritaire (outil écarté). |
| Burp MCP fonctionne avec Burp en `-Djava.awt.headless=true`. | Non prioritaire (outil écarté). |
| `chrome-devtools-mcp` accepte un proxy. | Lire `docs/configuration.md` du dépôt. |
| Options hors ligne d'osv-scanner (nom exact des drapeaux). | `osv-scanner scan --help` dans l'image après T4. |
| Nom du champ listant les serveurs MCP dans l'événement `system/init`. | Lire un stream-json réel d'un run avec un MCP de test. |
| Licence CodeQL pour des cibles non open source. | Lire les conditions GitHub CodeQL avant tout usage. |

Commandes de preuve rejouables (R6) :
- Stats GitHub : `gh api repos/<owner>/<repo> --jq '[.stargazers_count,.pushed_at,.license.spdx_id]'` (2026-11-25).
- Outils Pro de Burp : `gh api repos/PortSwigger/mcp-server/contents/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt --jq .content | base64 -d | sed -n 250,300p`.
- MCP d'osv-scanner : `gh api repos/google/osv-scanner/contents/cmd/osv-scanner/mcp/command.go --jq .content | base64 -d | grep -n Name:`.
- Semgrep et drapeaux Claude dans l'agent : `podman exec bh-agent sh -c 'semgrep mcp --help; claude --help | grep -i mcp'`.
- cwd de l'agent et nettoyage : `src/bh/runner/run.py` (`-w {WORK_ROOT}/{prog}`, `_WORK_SCRIPT`).

---

## 6. Sources

Claude Code (officiel) :
- https://code.claude.com/docs/en/cli-reference — `--mcp-config`, `--strict-mcp-config`, `--tools` (« doesn't affect MCP tools »), `--disallowedTools "mcp__*"`.
- https://code.claude.com/docs/en/mcp — chargement sans demande en `-p`, `MAX_MCP_OUTPUT_TOKENS` (25 000 par défaut), fichier au-delà de 50 000 caractères, recherche d'outils activée par défaut.
- https://code.claude.com/docs/en/hooks — matchers `mcp__<server>__.*`, `updatedMCPToolOutput`, champ `mcp_server` en PreToolUse.

Proxys :
- https://github.com/PortSwigger/mcp-server ; https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc
- https://portswigger.net/burp/documentation/desktop/getting-started/launch-from-command-line
- https://github.com/c0tton-fluff/caido-mcp-server ; https://docs.caido.io/app/tutorials/mcp ; https://docs.caido.io/app/tutorials/skills ; https://docs.caido.io/app/tutorials/headless_orchestration ; https://www.caido.io/blog/2026-03-06-caido-skill/ ; https://caido.io/blog/2026-07-14-agentic-pentesting-with-mcp/
- https://www.zaproxy.org/docs/desktop/addons/mcp-integration/ ; https://www.zaproxy.org/blog/2026-04-02-zap-mcp-server/ ; https://www.zaproxy.org/blog/2026-05-21-scanning-mcp-servers-with-zap/
- https://pypi.org/project/mitmproxy-mcp/

Navigateurs :
- https://github.com/microsoft/playwright-mcp ; https://playwright.dev/mcp/configuration/options
- https://github.com/ChromeDevTools/chrome-devtools-mcp

RE :
- https://github.com/morluto/rea ; https://github.com/morluto/rea/blob/main/docs/guides/web/web-source-location.md
- https://github.com/LaurieWired/GhidraMCP ; https://github.com/clearbluejar/pyghidra-mcp ; https://github.com/mrexodia/ida-pro-mcp
- https://github.com/radareorg/radare2-mcp ; https://github.com/zinja-coder/jadx-ai-mcp ; https://github.com/dnakov/frida-mcp
- https://github.com/denandz/sourcemapper ; https://github.com/BishopFox/jsluice

Offensif / plateformes :
- https://www.kali.org/tools/mcp-kali-server/ ; https://www.kali.org/tools/metasploitmcp/ ; https://www.kali.org/tools/caido/
- https://github.com/projectdiscovery/interactsh
- https://docs.hackerone.com/en/articles/16069027-july-2026-changelog
- https://github.com/awarexone/Agentic-Bug-Hunter ; https://github.com/H-mmer/pentest-agents ; https://github.com/transilienceai/communitytools ; https://github.com/h4ckologic/bughunter-ai

CVE / white-box :
- https://semgrep.dev/blog/2026/semgrep-mcp-server ; https://github.com/semgrep/mcp (archivé)
- https://github.com/google/osv-scanner (`cmd/osv-scanner/mcp/command.go`) ; https://github.com/StacklokLabs/osv-mcp
- https://glama.ai/mcp/servers/microsoft/github-advisory-mcp ; https://github.blog/changelog/2026-05-05-dependency-scanning-with-github-mcp-server-is-in-public-preview/
- https://advisories.gitlab.com/golang/github.com/github/github-mcp-server/CVE-2026-47427/
- https://glama.ai/mcp/servers/advanced-security/codeql-development-mcp-server
