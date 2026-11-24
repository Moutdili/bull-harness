# 09 — Vision headless : faire « voir l'écran » à l'agent

Date : 2026-11-25. Auteur : agent de recherche « vision » du swarm. Statut : **proposition, à valider par Mio**.
Légende : ✅ vérifié (source citée ou sortie d'outil) · 🟡 supposé (à mesurer) · ❓ inconnu.

## 1. Résumé

- État mesuré : l'agent n'a **aucun navigateur** (`chromium`, `chrome-headless-shell`, `playwright`, `firefox-esr` absents ; `node` v24.22.2 et `python3` présents). ✅ `podman exec bh-agent sh -c 'command -v …'`, 2026-11-25.
- Recommandation : un builtin **`bh-browse`** sur **Playwright Python** + **chrome-headless-shell**, installés au build (versions appariées), **un process par commande**, pas de MCP.
- Texte d'abord : l'arbre d'accessibilité (`page.aria_snapshot()`) va dans `raw/`, le résumé ≤ 25 lignes dans le contexte (~300-500 tokens 🟡).
- Image à la demande seulement (`--shot`), viewport 1024×768 = **1 036 tokens** ✅ (formule officielle), ou un recadrage d'élément (~350 tokens).
- CDP reste local : Playwright lance Chromium avec `--remote-debugging-pipe` (pipe, pas de socket) ✅ source Playwright.
- Tout le trafic de page passe par `--proxy-server=http://gate:8080` (option `proxy` de Playwright) ✅.
- Le vrai risque n'est pas le navigateur : c'est le **gate**. Une page charge 30-150 sous-ressources, souvent sur des CDN hors scope, au débit du programme (2-20 req/s). Il faut une règle « sous-ressources » côté navigateur et une décision de Mio côté gate.
- Un MCP navigateur est écarté : il contourne les hooks `Bash` (verrou, métriques, `raw/`), ajoute ses schémas d'outils à chaque tour, et rend des snapshots non bornés.

## 2. Tableau des options

| Option | Headless sans Internet | Proxy + CA maison | Sortie texte / image | Maturité, licence | Verdict |
|---|---|---|---|---|---|
| **Playwright Python** (lib) dans un builtin | ✅ `headless=True` par défaut. Navigateur téléchargé **au build** (`playwright install --only-shell chromium`), le build a le réseau. | ✅ `launch(proxy={"server": …, "bypass": …})` → `--proxy-server`. CA : NSS DB (`certutil`) ou `ignore_https_errors`. | ✅ `page.aria_snapshot()` (YAML), `page.screenshot()`, HAR (`record_har_path`), dialogs (`page.on("dialog")`). | PyPI 1.65.2 (2026-11-14), Chromium 159 embarqué. Apache-2.0. ✅ | **Retenu** |
| `python3-playwright` de Kali/Debian (1.55.0+ds-2) + `chromium` Kali | 🟡 | idem | idem | Paquet Debian « +ds » (132 Ko) : dépend de `python3-greenlet`, `python3-pyee` ; ni Chromium ni driver Node listés ✅. Playwright ne garantit que son Chromium embarqué : « use at your own risk » ✅. | Écarté (versions non appariées, driver ❓) |
| **playwright-cli** (`@playwright/cli`, Node) | ✅ daemon headless, se coupe après 1 h d'inactivité | 🟡 proxy par variables `PLAYWRIGHT_MCP_PROXY_SERVER` / `_BYPASS`, `PLAYWRIGHT_MCP_IGNORE_HTTPS_ERRORS` ✅ (doc), pas de clé proxy dans le schéma de config | Snapshot avec refs (`e15`) **inline par défaut** ; `screenshot --filename` ; `dialog-accept` ; `state-save`. Pas de HAR listé. | Apache-2.0. Annoncé « token-efficient » pour agents de code ✅ | Bonne alternative ; à envelopper pour borner la sortie |
| **Playwright MCP** (`@playwright/mcp`) | ✅ `--headless` | ✅ `--proxy-server`, `--proxy-bypass`, `--ignore-https-errors` | Snapshot d'accessibilité par défaut, `--snapshot-mode full|none`, `--image-responses allow|omit|only`, `--caps vision` | Apache-2.0. Le README lui-même conseille la CLI aux agents de code (schémas et arbres verbeux en contexte) ✅ | Écarté (voir §4.4) |
| **chrome-devtools-mcp** (Google) | ✅ `--headless`, `--isolated` | ✅ `--proxyServer`, `--acceptInsecureCerts`, `--chromeArg` | `take_snapshot` (arbre a11y, `filePath` possible), `take_screenshot`, `handle_dialog`, `list_network_requests` | Apache-2.0. **63 outils** (`--slim` réduit). **Télémétrie Google activée par défaut** (`--no-usage-statistics`, `--no-performance-crux`) ✅ | Écarté (télémétrie, taille du schéma, pas de hooks) |
| **agent-browser** (Vercel, CLI Rust) | ✅ daemon par `--session`, Chrome for Testing téléchargé par `agent-browser install` | ✅ `--proxy`, `--proxy-bypass`, `--ignore-https-errors`, `--headers`, `--executable-path`, `--args` | `snapshot -i` (refs `@e1`), `screenshot`, `dialog`, `network`, `eval` | Apache-2.0. Daemon + sockets locaux ; port de streaming WebSocket « OS-assigned » ✅ | Plausible, mais un binaire et un daemon de plus à auditer |
| **browser-use** | 🟡 | ❓ proxy local non documenté | — | MIT. **Exige un LLM** (passerelle Browser Use par défaut, ou clé OpenAI/Ollama) ✅ | Écarté (2ᵉ LLM, sortie réseau) |
| **Stagehand** (Browserbase) | 🟡 mode local « needs Chrome installed » | ❓ | `act/extract/observe` pilotés par LLM (clé modèle dans les exemples locaux) ✅ | MIT | Écarté (2ᵉ LLM) |
| **Chromium brut** (`--headless --dump-dom`, `--screenshot`, `--window-size`) | ✅ | ✅ `--proxy-server` (doc Chromium) | `--dump-dom` = DOM sérialisé **après exécution des scripts** ✅ ; `--screenshot` → `screenshot.png` ✅ | Stable, BSD. Pas d'interaction, pas de dialog, pas de HAR. | Utile en secours pour `--dump-dom` seulement |

Notes vérifiées :
- Depuis Chrome 132.0.6793.0, l'ancien mode headless n'existe plus que dans le binaire séparé `chrome-headless-shell` ✅. Playwright utilise ce binaire par défaut en headless, et `channel="chromium"` pour le « nouveau headless » ✅.
- Playwright passe déjà la plupart des flags anti-trafic de fond (`chromiumSwitches.ts`, branche main) ✅ : `--disable-background-networking`, `--disable-component-update`, `--disable-field-trial-config`, `--disable-breakpad`, `--disable-default-apps`, `--disable-extensions`, `--disable-sync`, `--metrics-recording-only`, `--no-first-run`, `--no-service-autorun`, `--disable-dev-shm-usage`, et `--disable-features=…OptimizationHints,NetworkTimeServiceQuerying,MediaRouter,HttpsUpgrades,…`.
- Playwright lance Chromium avec `--remote-debugging-pipe` (`chromium.ts`, `defaultArgs`) ✅. Le CDP ne touche donc **aucun socket** : il ne peut ni passer par le gate ni être refusé comme websocket.

## 3. Coût en tokens chiffré

### 3.1 Formule officielle (Anthropic, page Vision) ✅
- Coût = `⌈largeur / 28⌉ × ⌈hauteur / 28⌉` tokens visuels (un patch = 28×28 px).
- Tier haute résolution (« Claude 4.7 and later models », donc Opus 5.5 et Sonnet 5.5) : bord long ≤ **2 576 px**, ≤ **4 784** tokens. Au-delà, réduction à l'aspect constant.
- Tier standard (autres modèles) : bord long ≤ 1 568 px, ≤ 1 568 tokens.
- Prix donné par la doc : Opus 5.5 à 4 $ / M tokens en entrée. Sur Ultra, c'est du quota, pas des dollars.
- Claude Code `Read` : PNG, JPEG, GIF, WebP rendus comme image ; « Claude Code resizes and recompresses large images » ; refus au-delà de 128 Mo ✅. La taille cible exacte de Claude Code n'est pas documentée ❓.

### 3.2 Coût par capture (calculé avec la formule)

| Capture | Tier haute résolution | Tier standard |
|---|---|---|
| Viewport 1920×1080 | 2 691 (doc) | 1 560 (doc, réduit à 1456×819) |
| Viewport 1280×720 | 46 × 26 = **1 196** | 1 196 |
| **Viewport 1024×768 (cible)** | 37 × 28 = **1 036** | 1 036 |
| Viewport 800×600 | 29 × 22 = 638 | 638 |
| Recadrage d'élément 640×400 | 23 × 15 = **345** | 345 |
| Page entière 1280×3000 | réduite à 1099×2576 → 40 × 92 = **3 680** | réduite à 669×1568 → 24 × 56 = 1 344 |

### 3.3 Texte contre image (par page)

| Sortie | Tokens dans le contexte | Statut |
|---|---|---|
| Résumé `bh-browse` ≤ 25 lignes (~60 car./ligne, ~4 car./token) | **~300-500** | 🟡 à mesurer via `usage` |
| Snapshot ARIA complet d'une SPA | 2 000-15 000 | 🟡 ordre de grandeur ; reste dans `raw/`, jamais dans le contexte |
| Capture viewport 1024×768 | **1 036** | ✅ calculé |
| Capture pleine page 1280×3000 (Opus 5.5) | 3 680 | ✅ calculé |

- Une image reste dans l'historique : elle est relue à chaque tour suivant (en cache). Sur 30 tours restants, une capture de 1 036 tokens représente ~31 000 tokens relus 🟡.
- Règle : jamais de pleine page par défaut ; viewport 1024×768 ou `--clip <sélecteur>`.

### 3.4 Quand l'image est nécessaire
- **Texte suffit** : routes d'une SPA, formulaires et champs, présence d'un texte ou d'un bouton, effet d'un IDOR (le nom d'un autre utilisateur apparaît dans le snapshot), `alert()` intercepté (événement `dialog`), erreurs console, requêtes XHR (HAR).
- **Image utile** : mise en page trompeuse (clickjacking, superposition, UI redressing), CAPTCHA ou mur WAF à reconnaître, canvas ou contenu sans accessibilité, preuve visuelle pour la PoC.
- **Preuve PoC** : la capture est écrite dans `raw/` par défaut, mais **pas lue** par l'agent. L'humain et le rapport la consomment. L'agent ne la `Read` que pour décider.

## 4. Recommandation et interface du builtin

### 4.1 Option retenue
- Playwright Python (PyPI, épinglé) + `chrome-headless-shell` installé au build par `playwright install --with-deps --only-shell chromium` ✅ (commande de la doc).
- Pilote dans un module séparé, lancé en sous-process. `src/bh/agent/` reste stdlib : seul le sous-process importe `playwright` (dérogation à valider par Mio).
- Un navigateur **par commande** : pas de daemon à surveiller, le `timeout` tue tout, `init: true` récolte les orphelins. La session applicative (cookies posés par un login de formulaire) est gardée par `storage_state` dans `raw/browse-state-<identité>.json`.
- Les identités du harnais restent injectées par le gate : `bh-browse --as X` ajoute `X-BH-Identity: X` via `extra_http_headers` (même contrat que les autres builtins, `c.IDENTITY_HEADER`).

### 4.2 Interface

```
bh-browse <url> [--as ID] [--shot] [--clip CSS] [--full]
          [--fill CSS=VALEUR]... [--click CSS]... [--submit CSS]
          [--wait-for CSS|networkidle] [--routes] [--xss MARQUEUR] [--timeout S]
```

- Sans option : navigue, attend le chargement, écrit DOM + snapshot ARIA + HAR + console, rend le résumé.
- `--fill/--click/--submit` : étapes exécutées dans l'ordre de la ligne (inscription, login, action d'un rôle). Sélecteurs Playwright (CSS ou `role=button[name="…"]`).
- `--routes` : clique les liens internes et note chaque URL après `pushState` (routes SPA). Les nouveaux endpoints vont dans `endpoints.jsonl` (source `browse`), comme `bh-crawl`.
- `--xss M` : enregistre un handler `dialog` qui note `type` et `message`, puis `dismiss()` ✅ (sans handler, Playwright ferme les dialogs en silence ✅). Verdict `xss: CONFIRMED` si un dialog contient `M`, ou si `document.title`/une propriété sentinelle contient `M`.
- `--shot` : capture viewport 1024×768 en PNG ; `--clip` recadre un élément ; `--full` pleine page (coût affiché).

### 4.3 Sortie (≤ 25 lignes) et brut

```
bh-browse https://app.example/dashboard as=alice: 200, title "Dashboard", 2.8 s [ok]
  final url: https://app.example/dashboard#/settings
  requests: 41 (in scope 33, blocked 8: cdn.x.net ×6, fonts.gstatic.com ×2)
  xhr: GET /api/v2/me 200 · GET /api/v2/orgs/17/users 200 · POST /api/v2/events 204
  dialogs: alert("bh7f3") ← xss CONFIRMED (marker bh7f3)
  console: 2 errors (TypeError at main.js:1:8812)
  forms: 1 — #profile (name, email, avatar) → PUT /api/v2/users/42
  new routes: /settings /billing /admin/users (+3 in raw)
  a11y: heading "Settings" · textbox "Email" = alice@… · button "Save" · link "Admin"
  shot: raw/browse-…/shot.png 1024x768 ≈ 1036 tokens (Read it only if needed)
raw: /work/.bh/raw/browse-app.example_dashboard-1764070000/
```

Brut dans `raw/browse-<slug>-<ts>/` (même schéma que `Job` dans `tools.py`) : `dom.html`, `aria.yml`, `har.json` (`record_har_path`, contexte fermé proprement ✅), `console.log`, `dialogs.jsonl`, `routes.txt`, `shot.png`, `cmd.txt`.
L'agent lit l'image avec `Read raw/…/shot.png` **seulement** s'il le décide. Aucun hook n'est nécessaire : les hooks actuels ne matchent que `Bash` (`container/agent/hooks/settings.json`).

### 4.4 Builtin contre MCP navigateur

| Critère | `bh-browse` (Bash) | MCP navigateur |
|---|---|---|
| Verrou, règles programme, métriques | ✅ passe par le PreToolUse `Bash` existant | ❌ hors matcher `Bash` ; il faudrait un matcher `mcp__…` et réécrire le verrou |
| Sortie bornée, brut sur disque | ✅ ≤ 25 lignes par construction | ❌ snapshot renvoyé après chaque action (`--snapshot-mode full` par défaut côté Playwright MCP) |
| Coût fixe par tour | 0 (un nom dans la doctrine) | Schémas d'outils à chaque tour (63 outils pour chrome-devtools-mcp) |
| Session persistante, raisonnement pas à pas | 🟡 `storage_state` entre commandes | ✅ natif |
| Surface d'attaque | un module Python | serveur MCP Node + télémétrie à couper |

### 4.5 Contraintes du gate et flags

- **Proxy** : `proxy={"server": "http://gate:8080"}` → `--proxy-server` ✅. Avec un proxy HTTP, Chromium envoie le nom d'hôte au proxy (CONNECT) et ne résout pas lui-même 🟡 ; cohérent avec l'absence de DNS externe.
- **CA du gate** : Chromium Linux lit la **NSS Shared DB**, pas `/etc/ssl/certs` (doc Chromium : `$HOME/.local/share/pki/nssdb` depuis M146 ; `certutil -d sql:… -A -t "C,," -n <nom> -i <ca>`) ✅. Donc soit `certutil` dans l'entrypoint (paquet `libnss3-tools`), soit `ignore_https_errors=True`. Le second est acceptable ici : le gate vérifie le certificat amont (`ssl_insecure` = False par défaut dans mitmproxy ✅). Recommandation : NSS DB, `ignore_https_errors` en repli.
- **Websockets** : refusés par le gate (`addon.py:348`) ✅. Effet : chat, notifications temps réel, HMR et `socket.io` en mode websocket échouent. `socket.io` sait se replier sur le long-polling HTTP 🟡. Le résumé doit compter les websockets refusés.
- **CDP** : pipe local, pas de websocket ✅ (§2). Si un jour un outil utilise `--remote-debugging-port`, `NO_PROXY=localhost,127.0.0.1` couvre la boucle locale ; Chromium contourne aussi le proxy pour la boucle locale par défaut (Playwright ajoute `<-loopback>` seulement s'il doit la proxifier) 🟡.
- **HTTP/2** : mitmproxy l'active par défaut (`http2` = True) ✅ et l'addon traite `req.is_http2` ✅. Rien à faire.
- **Service workers** : `service_workers="block"` ✅. Sinon un SW sert des réponses en cache et masque les requêtes au HAR et au gate.
- **Télémétrie** : couverte par les flags Playwright (§2). Ajouter `--no-pings` et `--disable-domain-reliability` (doc chrome-launcher) ✅. Le gate journalise tout reste : premier critère d'acceptation = zéro requête vers `*.google.com`/`*.gvt1.com` dans les journaux du gate pendant une page de lab 🟡.
- **Sous-ressources hors scope** : chaque CDN tiers produit un `blocked` sur le board. Proposition : `context.route("**/*")` abandonne localement (sans réseau) les requêtes vers un hôte hors de l'origine cible et de ses sous-domaines, et les compte dans le résumé. Décision de Mio requise : autoriser ou non un GET passif vers des CDN pour que la SPA se rende.
- **Débit** : une page = 30-150 requêtes 🟡. À 2 req/s, 15-75 s par page. Bloquer `image`, `font`, `media` via `route.request.resource_type` (sauf avec `--shot`) divise le volume 🟡.
- **Garde 404** : favicons et sourcemaps manquants peuvent compter dans la rafale 404 🟡. Bloquer `*.map` et `/favicon.ico` côté route.
- **Sandbox Chromium** : `chromium_sandbox=False` par défaut dans Playwright ✅ ; avec `cap_drop: ALL` et `no-new-privileges`, le sandbox Chromium ne démarrerait pas de toute façon 🟡. Conséquence : un exploit de rendu dans une page hostile donne le conteneur agent, qui n'a aucune route. Risque accepté, à écrire dans `architecture.md` (limites).

### 4.6 Ressources
- Disque : ~281 Mo pour Chromium complet selon la doc Playwright ✅ ; `--only-shell` plus petit ❓.
- Mémoire : 150-400 Mo par page headless 🟡 ; compatible avec `mem_limit: 6g` à un navigateur à la fois.
- `/dev/shm` : 64 Mo par défaut sous podman 🟡 ; `--disable-dev-shm-usage` est déjà passé par Playwright ✅.
- Démarrage : 0,5-2 s par lancement 🟡. À mesurer ; un daemon ne se justifie que si le lancement dépasse ~10 % du temps d'une page (le débit du gate domine).
- `pids_limit: 2048` : Chromium lance ~10-20 process 🟡, sans problème.

## 5. Plan d'intégration (swarm)

Ordre de merge : T1 → T2 → T3 → T4 → T5 → T6. Un fichier, un propriétaire.

| Tâche | Fichier(s), propriétaire exclusif | Critère d'acceptation binaire |
|---|---|---|
| T1 Image | `container/agent/Containerfile` (+ `check.sh`) | `podman build` OK ; dans l'agent, `python3 -c "import playwright"` rc=0 et le binaire headless shell existe sous `PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright` (lisible par `hunter`) |
| T2 CA navigateur | `container/agent/entrypoint.sh` (+ `libnss3-tools` dans `packages.txt`) | `certutil -d sql:/home/hunter/.local/share/pki/nssdb -L` liste la CA du gate ; une page HTTPS du lab via le gate charge sans `ignore_https_errors` |
| T3 Pilote | `src/bh/agent/browse.py` (nouveau) | Sur Juice Shop (lab) : `bh-browse http://10.231.0.10:3000/` sort ≤ 25 lignes, `raw/…/{dom.html,aria.yml,har.json}` existent, ≥ 1 route `#/…` absente de `endpoints.jsonl` avant le run y est ajoutée |
| T4 Dispatch et classement | `src/bh/agent/main.py`, `src/bh/agent/contract.py`, `container/agent/bin/bh-browse` (lien) | `bh-browse` est classé (mapper sans `--xss`, scanner avec) ; un programme sans scanners refuse `bh-browse --xss` avec `[bh-rules]` ; `tests/agent/test_browse_dispatch.py` passe |
| T5 Preuve XSS | `tests/agent/test_browse.py` (nouveau) | Sur le XSS DOM connu de Juice Shop (`/#/search?q=<iframe src="javascript:alert('bhX')">`) : sortie contient `xss CONFIRMED (marker bhX)` ; sur une recherche bénigne : pas de `CONFIRMED` |
| T6 Mesure réseau et tokens | `docs/research/09-vision-headless.md` (moi, section mesures) | Journal du gate pendant T5 : 0 requête hors lab ; `usage.input_tokens` d'un tour avec résumé et d'un tour avec `Read shot.png` relevés dans le stream-json |

Doctrine (fichier tenu par le propriétaire de `src/bh/runner/prompt.py`) : une ligne « `bh-browse` texte d'abord ; `--shot` seulement pour une mise en page ou une preuve ; ne `Read` une image que pour décider ».

## 6. Incertitudes

1. ❓ **Sous-ressources hors scope** : sans CDN, beaucoup de SPA ne se rendent pas. Les autoriser en GET passif touche à la règle « hors scope jamais ». Décision Mio.
2. 🟡 **Débit** : temps par page au débit réel d'un programme (2-20 req/s) non mesuré ; peut rendre `--routes` trop lent.
3. ❓ **Redimensionnement de `Read`** : la taille cible de Claude Code n'est pas documentée ; le coût réel d'une capture doit être lu dans `usage`, pas seulement calculé.
4. 🟡 Coût texte (~300-500 tokens) et taille d'un snapshot ARIA : estimations, à mesurer sur le lab.
5. ❓ Comportement d'un vrai WAF (Cloudflare, Akamai) face à `chrome-headless-shell` : détection probable ; le gate détecte déjà les challenges (`addon.py`, motifs WAF), cela devient une todo `waf`.
6. 🟡 Websockets : part des SPA cibles qui cassent sans eux, et repli long-polling, non mesurés.
7. ❓ Taille disque de `--only-shell` et temps de démarrage dans l'agent.
8. 🟡 Le refus `[bh-lock]` : faut-il exiger crawl/content/scan avant `bh-browse` ? Proposé : non (c'est un outil de cartographie), oui pour `--xss`.

## 7. Sources

- Anthropic, Vision (formule, tiers, tableau) : https://platform.claude.com/docs/en/build-with-claude/vision
- Claude Code, Tools reference (Read et images) : https://code.claude.com/docs/en/tools-reference
- Playwright, aria snapshots (Python) : https://playwright.dev/python/docs/aria-snapshots
- Playwright, BrowserType (proxy, executable_path, record_har_path, service_workers, chromium_sandbox) : https://playwright.dev/python/docs/api/class-browsertype
- Playwright, Dialog : https://playwright.dev/python/docs/api/class-dialog
- Playwright, Browsers (headless shell, `--only-shell`, tailles, proxy à l'installation) : https://playwright.dev/python/docs/browsers
- Playwright, sources `chromiumSwitches.ts` et `chromium.ts` (flags par défaut, `--remote-debugging-pipe`, proxy) : https://github.com/microsoft/playwright/tree/main/packages/playwright-core/src/server/chromium
- PyPI playwright 1.65.2 : https://pypi.org/project/playwright/
- Debian python3-playwright : https://packages.debian.org/sid/python3-playwright ; Kali pool : https://ftp.riken.jp/Linux/kali/pool/main/p/python-playwright ; Kali chromium : https://www.kali.org/tools/chromium
- Playwright MCP : https://github.com/microsoft/playwright-mcp
- playwright-cli : https://github.com/microsoft/playwright-cli
- chrome-devtools-mcp : https://github.com/ChromeDevTools/chrome-devtools-mcp ; outils : https://github.com/ChromeDevTools/chrome-devtools-mcp/blob/main/docs/tool-reference.md ; config : https://developer.chrome.com/docs/devtools/agents/get-started/configuration
- agent-browser : https://github.com/vercel-labs/agent-browser ; config : https://agent-browser.dev/configuration
- browser-use : https://github.com/browser-use/browser-use
- Stagehand : https://github.com/browserbase/stagehand
- Chrome headless : https://developer.chrome.com/docs/chromium/headless ; CLI (`--dump-dom`, `--screenshot`, `--window-size`) : https://developer.chrome.com/docs/automation-and-testing/headless-cli
- Flags pour outils (trafic de fond) : https://github.com/GoogleChrome/chrome-launcher/blob/main/docs/chrome-flags-for-tools.md
- Chromium, network settings (`--proxy-server`) : https://www.chromium.org/developers/design-documents/network-settings/
- Chromium, Linux cert management (NSS DB, certutil) : https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux/cert_management.md
- mitmproxy options (`ssl_insecure`, `http2`, `websocket`) : https://docs.mitmproxy.org/stable/concepts/options/
- Repo : `container/compose.yaml`, `container/agent/Containerfile`, `container/agent/entrypoint.sh`, `container/agent/hooks/settings.json`, `src/bh/gate/addon.py:348-351`, `src/bh/agent/tools.py`, `src/bh/agent/contract.py`.
