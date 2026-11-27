# bull-harness — architecture

Écrite en v0 (2026-11-22), tenue à jour vague après vague ; état à `b160269` (W1 à W3 fusionnées). Les blocs livrés
depuis ont leur section à la fin (« Blocs livrés en W1 à W3 »), et les schémas sont dans `docs/diagrams.md`. Ce que le
dépôt n'a pas encore est marqué « W4 » ou « non construit ». Les points ⚠ datent de la v0.

## Contraintes fixées

| Contrainte | Valeur | Conséquence |
|---|---|---|
| CVP | tier **Defense** (individuel) | Source primaire : Defense est le tier prévu pour les bug bounty hunters, et couvre le triage et la validation de vulnérabilités. L'exploit dev et les outils offensifs relèvent de Red Team, **réservé aux organisations sur API/Enterprise**. Les refus restent possibles (faux positifs) : refus → todo humaine. |
| Plan Claude | **Pro** | Fenêtre glissante de 5 h + plafond hebdo, partagés avec claude.ai. Pas de crédits API. → **1 agent à la fois**, superviseur qui dort jusqu'au reset, économie de tokens prioritaire. ⚠ Accès Opus sur Pro non confirmé : modèle configurable. |
| Conteneurs | **Podman 5.8.9 rootless** + podman-compose 1.6.0 | Pas de socket root à monter, ce qui évite la classe de CVE-2026-14784. Le compose doit rester compatible docker compose. ⚠ Vérifier `internal: true` sous podman-compose. |
| Plateformes | **YesWeHack, Intigriti** puis H1/Bugcrowd | Règles par programme : en-tête obligatoire (`X-Intigriti-Username`, `User-Agent: Intigriti-<user>`, `Infomaniak-YWH-Bugbounty`…) et plafond de requêtes (3 à 20 req/s selon le programme). |
| Claude Code | 2.1.330 | Supérieur à 2.1.121 : `updatedToolOutput` en PostToolUse doit être disponible pour tous les outils. ⚠ À tester. |

## Vue d'ensemble

```
 hôte Fedora (Mio / Claude orchestrateur)
 ├─ bh (CLI)  ─────────────┐
 ├─ ui (web, SSE)          │  SQLite board : facts (+ blockers) / intents / findings / todos submit
                           ▼
 ┌────────── réseau "egress" ──────────┐
 │  gate  (mitmproxy, relais :8081)    │ ← seul conteneur avec Internet
 │   · allowlist = scope en dur        │
 │   · token bucket req/s par programme│
 │   · injection en-têtes + cookies    │
 │   · journal caviardé de chaque flux │
 └──────────────┬──────────────────────┘
        réseau "sandbox" (internal, pas de route)
 ┌──────────────┴──────────────────────┐
 │  agent (kali-rolling + headless)    │
 │   · claude -p (headless, OAuth Pro) │
 │   · hooks Pre/PostToolUse           │
 │     (Bash et mcp__.*)               │
 │   · /opt/bh/bin : alias + builtins  │
 │   · MCP stdio : bh, hexstrike (W3)  │
 │   · skills (W3)                     │
 └─────────────────────────────────────┘
 ┌─────────────────────────────────────┐
 │  judge (même image, même gate)      │ ← vérificateur : son /work (var/judge),
 │   · bh-agent replay + claude -p     │   ses process, son /tmp, user `judge`
 └─────────────────────────────────────┘
```

## Composants

### 1. `scope/` — scope en dur (cœur sécurité)
- Un fichier YAML par programme : `scopes/<platform>/<slug>.yaml`.
- Champs : `in_scope[]` (hôtes, wildcards, CIDR, apps), `out_of_scope[]`, `support[]` (hôtes de support, voir §2),
  `websockets` (`true` pour les ouvrir vers les cibles ; absent ou `null` = refusés), `required_headers{}`, `user_agent`, `max_rps`, `automation_allowed`, `forbidden_vulns[]`, `identities[]` (références vers des secrets, jamais les secrets eux-mêmes), `source`, `synced_at`, `hash`.
- `enforce(url|host|ip) → allow|deny + raison` : **une seule fonction**, utilisée par le proxy, les builtins et `bh`. Un out-of-scope l'emporte toujours sur un in-scope.
- Un actif découvert hors scope est consigné (fait `out-of-scope`, un par run), **jamais** ajouté au scope ni ciblé.
- Sync : seul l'import YesWeHack d'un programme public existe (`bh scope import ywh`, `src/bh/scope/yeswehack.py`) ;
  l'API Intigriti et `bounty-targets-data` ne sont pas construits. Un import n'élargit jamais un scope ; l'humain relit.
  Les programmes MSRC sont écrits à la main depuis un relevé d'hôtes (`scopes/msrc/`, `docs/research/21-…`).

### 2. `gate/` — sortie réseau contrôlée
- HTTP(S) : addon mitmproxy. Refuse ce qui est hors scope (403 + fait `blocked` sur le board), limite le débit par programme, injecte les en-têtes requis et les cookies de session, écrit le HAR.
- DNS : non construit (TODO 1.2). La sandbox n'a aucune résolution externe : le gate résout lui-même et vérifie chaque
  IP (`policy.check_ip`) avant de s'y connecter.
- Autre TCP : non construit, volontairement (TODO 1.3, pas de SOCKS5) ; le TCP brut est coupé par le gate (`tcp_start`),
  sauf un tunnel `passthrough` enregistré au CONNECT. Pas de scan SYN brut.
- Allowlist système séparée : `api.anthropic.com` et ses dépendances (pour `claude`), dépôts de paquets au moment du build seulement.
- Allowlist **passive** séparée (web.archive.org, CommonCrawl, OTX, urlscan, crt.sh, sources subfinder) : GET seulement, ni cookies ni en-têtes de programme, débit propre. Un hôte passif n'est jamais une cible (voir `research/07-repos-mio.md`).
- **Hôtes de support** (`support[]` du scope, `{value, kind: auth|assets|sso|passthrough, note, token_paths?,
  get_paths?}`,
  domaine ou joker, domaine exact pour `sso` et `passthrough` ; une valeur qui recouvre un `in_scope` ou un support
  d'un autre kind est refusée au chargement). `enforce.check` rend une troisième réponse (`allowed: false`,
  `support: <kind>`, sans règle d'exclusion), que le gate classe `support` :
  - `assets` (scripts et styles que les pages de la cible chargent, ex. `res.cdn.office.net`) : GET et HEAD sans corps,
    depuis tout client du sandbox, ports 80/443, IP publiques seulement ; ni en-têtes de programme, ni identité, ni
    `Cookie` / `Authorization`. `bh-browse` les laisse passer (liste lue dans `scope.yaml` de `BH_DIR`, ou
    `BH_SUPPORT_ASSETS`).
  - `auth` (notre propre connexion, ex. `login.live.com`) : seulement depuis les sources d'enrôlement (`_from_gate` :
    le gate et `bh-login`), méthodes du login (GET, HEAD, OPTIONS, POST), cookies du navigateur de login laissés tels
    quels. L'agent et le juge sont refusés (« login host, enrollment only »), au CONNECT comme à la requête ;
    `bh-browse` les bloque aussi localement. Les URL d'un login (`login_url`, `goto` d'une recette) peuvent y pointer ;
    la sonde et les `origins` d'une identité, jamais.
  - `sso` (la connexion silencieuse que l'appli fait en cours d'usage, ex. l'iframe `GET …/oauth2/v2.0/authorize` et
    l'échange PKCE `POST …/oauth2/v2.0/token` de `login.microsoftonline.com`) : GET et HEAD sans corps, POST seulement
    sur les `token_paths` du scope (chemins absolus, `*` = un segment entier ; un segment encodé, pointé ou vide ne
    correspond jamais) ; les sources d'enrôlement gardent les méthodes du login. Le GET du chasseur et du juge est
    borné aux `get_paths` (I13 : mêmes formes, comparées en préfixe sur des segments entiers, `/*/oauth2/v2.0/authorize`
    couvre `/t/oauth2/v2.0/authorize/x` mais ni `/a/b/oauth2/…` ni `…/authorizeX` ; aucun `get_paths` déclaré : aucun
    GET), refus « GET only under its declared get_paths » ; bh-browser (l'appli elle-même) lit l'hôte partout.
    Ni en-têtes de programme, ni User-Agent du programme, ni en-têtes d'identité (pas d'`Authorization`) : sous
    `X-BH-Identity`, seulement les cookies de la jarre de cette identité pour cet hôte (`_apply_identity(cookies_only)`),
    et ses `Set-Cookie` retournent dans la jarre, masqués pour le client comme sur une cible. L'enrôlement garde les
    cookies des hôtes `sso` et de leurs domaines parents (`enroll._host_ok`). Une URL de login peut pointer sur un
    hôte `sso` ; la sonde et les `origins` d'une identité, jamais.
  - `passthrough` (un challenge anti-bot tiers, ex. `challenges.cloudflare.com` de Turnstile) : CONNECT sur 443
    seulement, depuis bh-browser seulement (B2 : l'agent, le juge et l'enrôlement sont refusés, « browser only »),
    décidé sur le nom, IP vérifiée publique comme ailleurs, puis **TLS jamais intercepté**. Mécanisme,
    mitmproxy 12.3.1 : les hôtes passthrough du scope actif vont dans les options officielles `ignore_hosts`
    (`^hôte:443$`, comparé au SNI du ClientHello ; https://docs.mitmproxy.org/stable/howto/ignore-domains/) et
    `show_ignored_hosts`, pour que le tunnel ignoré lève encore les événements TCP (`tcp_start`, `tcp_message` ;
    https://docs.mitmproxy.org/stable/api/events.html). Pas `tls_clienthello` + `ignore_connection` : ce chemin relaie
    par un `TCPLayer(ignore=True)` sans flux ni événement (source 12.3.1 : `proxy/layers/tls.py`, `layers/tcp.py`),
    donc rien à compter ni à borner. Le TCP brut reste refusé pour tout tunnel que le CONNECT n'a pas enregistré
    comme passthrough, et pour un tunnel dont les premiers octets ne sont pas un ClientHello TLS. Un SNI qui n'est pas
    l'hôte du CONNECT n'est pas ignoré, donc intercepté, et toute requête déchiffrée vers un hôte passthrough est
    refusée. Bornes (`PassthroughGuard.from_env`) : 20 tunnels neufs par minute, 6 ouverts, 16 Mio et 600 s par
    tunnel (`BH_PASSTHROUGH_PER_MIN`, `_OPEN`, `_MAX_BYTES`, `_MAX_SECONDS` ; une valeur nulle, négative ou illisible
    garde le défaut). Un tunnel qui franchit une borne ou sa durée est fermé (voir « Fermeture » plus bas).
    Journal : événement `passthrough` {hôte, octets montants et descendants, durée}, rien d'autre ; les octets ne sont
    pas gardés en mémoire. Aucune identité ni en-tête interne n'y entre : `bh-browse` pose `X-BH-Identity` requête par
    requête (plus d'`extra_http_headers`), vers les cibles et les hôtes `sso` seulement ; et comme Playwright reporte
    les en-têtes d'une route sur ses redirections, le gate refuse une réponse de cible ou `sso` qui redirige vers un
    hôte passthrough quand la requête portait `X-BH-Identity`.
  - Tous : seau de débit propre (`SUPPORT_RPS` 4 req/s, rafale 8 ; passthrough : la garde de tunnels), une ligne
    `class: support` dans `flows.jsonl` (passthrough : l'événement ci-dessus), aucun fichier d'échange, jamais compté
    comme test, jamais dans le graphe d'actifs (`assets.py` ne garde que la classe `target`), ni pause WAF, ni garde
    d'énumération.
  - `bh-browse` laisse passer les autres cibles du scope (ex. le hub de chat), les hôtes `assets`, `sso` et
    `passthrough` (listes lues dans `scope.yaml` de `BH_DIR`, ou `BH_SUPPORT_ASSETS`, `BH_SUPPORT_SSO`,
    `BH_SUPPORT_PASSTHROUGH`, `BH_TARGET_HOSTS`), ne bloque rien sur un hôte passthrough (ni image ni source map), et
    compte les requêtes `sso` et `passthrough` dans son résumé.
- **Websockets** : refusés par défaut. Avec `websockets: true` dans le scope : vers les **cibles** seulement (support,
  passif et hors scope refusés), handshake GET jugé comme une requête cible (scope, Host, identité, en-têtes de
  programme, débit), au plus `BH_WS_MAX_OPEN` (2) connexions ouvertes. Sur un programme qui a un hôte passthrough, le
  handshake est réservé à bh-browser (B2, « browser only »). Hooks officiels mitmproxy
  (`websocket_start` / `websocket_message` / `websocket_end`) : par connexion, au plus `BH_WS_MSGS_PER_MIN` (12)
  messages client par minute glissante, `BH_WS_MAX_BYTES` (64 Kio) par message client (16 fois plus pour un message
  serveur), `BH_WS_MAX_SECONDS` de vie : 600 s, 3600 s pour bh-browser (`WsLimits.from_env(browser=True)`, la page de
  chat reste ouverte ; `BH_WS_MAX_SECONDS`, s'il est posé, vaut pour les deux). Trames binaires comptées comme les
  autres. Au premier dépassement : la trame est abandonnée (`drop()`), la connexion fermée (voir « Fermeture »), et
  toute trame suivante de la connexion abandonnée aussi (fail-closed si elle survit), avec **un seul** événement
  `blocked` par connexion (`closed: true|false`), pas un par trame. Chaque message, dans les deux sens, est journalisé
  (`events.jsonl`, `ws-message` : taille, sha256, 200 premiers caractères caviardés par `redact.text`, rien pour une
  trame binaire).
- **`browser_only`** (clé du scope : préfixes d'URL `https://hôte/chemin` d'une cible, hôte exact, sans joker ni query ;
  un hôte qui n'est pas une cible est refusé au chargement) : quelle que soit la méthode, seul bh-browser y accède ; le
  chasseur, le juge et l'enrôlement reçoivent « browser only: … is driven through bh-browser (bh-web) ». Comparé large,
  comme une exclusion (schéma et port quelconques, casse ignorée, `/Chathub/` couvre `/chathub;x` et `/chathub%..`).
- **bh-browser** (navigateur persistant, service compose `browser`, `BH_BROWSER_HOST`) : reconnu par son adresse,
  résolue comme celle de bh-login (cache 60 s, une relecture au plus toutes les 5 s pour une IP inconnue). Son trafic
  porte l'identité que l'hôte y a chargée, lue dans `<state>/browser-identity.json` (`{program, identity, loaded_at}`,
  relu sur mtime ; ignoré pour un autre programme, un nom inconnu ou malformé, `null`) ; jamais un `X-BH-Identity` de
  la page. Effets : flux et événements journalisés sous cette identité, méthodes réservées aux identités (PUT, PATCH,
  DELETE) permises, `Set-Cookie` versés dans la jarre de l'identité mais **non masqués** (ce sont ses cookies) ; rien
  n'est injecté (il a ses propres cookies et en-têtes). Jamais mis en pause par la garde WAF, jamais compté par la garde
  404 (un humain y passe les challenges, I6) ; ses 401 ne déclarent pas la session de la jarre morte.
- **Canaris** (I1, `gate/canary.py`) : `BH-SECRET-<16 hex>` est cherché dans l'URL et le corps de chaque requête, le
  corps de chaque réponse et chaque trame websocket (deux sens), sur tout le contenu décodé (gzip, deflate, br, zstd,
  sortie bornée à 2 Mio : une bombe de décompression coûte 2 Mio) avant toute troncature. Chaque occurrence donne un
  événement `{kind: "canary", token, where: request-url|request-body|response-body|ws-client|ws-server, host, url
  (caviardée), identity, client: browser|agent|judge|login|other, run, ts, program}` ; rien autour du jeton n'est
  gardé. Observation seule : la recherche ne décide jamais du flux. Le relais (trafic de l'API Claude) n'est pas fouillé.
- **Sonde de session** (`bh.accounts.enroll.probe`) : l'enrôlement (`_from_gate` : la boucle locale du gate, bh-login)
  n'emprunte jamais une session, sauf la sonde de l'hôte : `X-BH-Probe: 1` **depuis la boucle locale du gate**
  garde son `X-BH-Identity`. Depuis bh-login, l'agent ou bh-browser le marqueur ne vaut rien. Il est retiré de toute
  requête avant l'amont, quel que soit l'émetteur.
- **En-têtes par origine** (I19, `origin_headers` de la session : `{origine: {Authorization: valeur}}`, capturés à
  l'enrôlement) : injectés vers cette origine exacte seulement (schéma, hôte et port ; ils priment sur l'en-tête par
  défaut), même hors des `origins` de l'identité ; jamais dans un journal ni un fichier de flux (`<identity:nom>`).
- **Fermeture** (I18) : `flow.kill()` ne ferme ni un websocket ni un tunnel TCP en mitmproxy 12.3.1 (`Flow.kill` :
  « we cannot kill flows in transit », seul le calque HTTP le vérifie). `close_connection` annule la tâche de lecture
  de la connexion client, comme le chien de garde d'inactivité de mitmproxy (`proxy/server.py`,
  `ConnectionHandler.on_timeout`) ; le gestionnaire est trouvé via l'addon `proxyserver` (`Proxyserver.connections`
  par id client), puis `handle_client` ferme tous les transports de ce client. Ce sont des internes de la 12.3.1, pas
  une API : s'ils manquent, le trou noir reste (chaque message suivant abandonné) et l'événement dit `closed: false`.

### 3. `agent/` — conteneur Kali
- `kalilinux/kali-rolling` + `kali-linux-headless` + outils Go ProjectDiscovery + ffuf, etc. La liste des outils est déclarée dans des manifests de plugins, pas en dur dans le Containerfile.
- `claude` en headless avec `CLAUDE_CODE_OAUTH_TOKEN` (⚠ obtenu via `claude setup-token`, à vérifier). Variables d'environnement proxy forcées.
- Pas de secrets cibles dans le conteneur : les cookies sont injectés par le gate.

### 4. `tokens/` — économie de tokens
- **Hook PreToolUse** (`bh-agent hook-pre`, `src/bh/agent/hooks.py`, déclaré dans `container/agent/hooks/settings.json`
  pour `Bash` et pour `mcp__.*`) : journalise chaque appel dans `commands.jsonl` (outil, classe, décision) et applique
  les règles du programme et le verrou (§5). Il ne réécrit aucune commande : la réécriture vers un filtre de recette
  (`bhf`, `updatedInput`) prévue en v0 n'existe pas.
- **Hook PostToolUse** (`bh-agent hook-post`) : sur `Bash`, au-delà de `BH_TRUNC_CHARS` (8000 caractères par défaut),
  la sortie devient tête + queue + le chemin du brut sous `raw/` (`updatedToolOutput`). Sur `mcp__.*`, aucune
  réécriture (la forme du résultat est celle du serveur) : une sortie trop longue est notée dans `trunc.jsonl`.
- **Mineur** (le « watchdog ») : lit le JSONL des hooks, extrait préfixe + emplacements d'argument et classe par `économie × fréquence`. Il propose, il n'applique pas.
- **Compilateur d'alias** : abandonné le 2026-11-25 (gain mesuré ~0,3 % d'un run, TODO 2.6) ; aucun alias n'est écrit.
- **Calibrage sur Claude** : pas d'API key sur Pro → mesure différentielle via `claude -p --output-format json` (champ `usage`), avec et sans le symbole. ⚠ À valider : bruit dû au cache.
- **Index** : abandonné avec les alias ; rien n'est injecté après le system prompt.

### 5. `agent/` — arsenal (builtins) et verrou d'outils
Code du sandbox, stdlib seule, monté en lecture seule dans l'agent (`src/bh/agent`). Un seul exécutable
`bh-agent`, des liens `bh-recon`, `bh-crawl`, `bh-content`, `bh-scan`, `bh-params`, `bh-sqli`, `bh-xss`, `bh-note`.
- Chaque builtin : passe par le gate au débit du programme, `--as <identité>`, brut dans `raw/`, résumé ≤ 25 lignes,
  couverture enregistrée dans `coverage.json`, endpoints dans `endpoints.jsonl`.
- `bh-crawl` = katana + extracteur maison des chemins cités dans le JS/HTML (avec le verbe HTTP quand il est visible).
- **Verrou** (hook PreToolUse) : `curl`/`wget`/`python`… vers une origine sont refusés tant que crawl, content et scan
  n'y ont pas tourné. Le message `[bh-lock]` donne les commandes exactes.
- **Outils MCP** (W3) : le même hook PreToolUse voit chaque appel `mcp__<serveur>__<outil>` et le classe avec la table
  de `src/bh/agent/mcp_policy.py` (mapper, scanner, request, note, passive, browser) : un outil absent de la table est
  refusé, un scanner l'est quand le programme interdit les scanners, un outil `request` est sous le même verrou que
  `curl` sur les origines de ses URL, et le juge n'a aucun outil MCP. Une erreur du hook refuse l'appel (à l'inverse
  de `Bash`, où il laisse passer : le gate reste la frontière).
- **Skills** (W3) : une méthode par classe ou par surface, `src/bh/skills/<nom>/SKILL.md`, que l'agent charge avant
  de tester ; elles prennent la place des cartes épinglées (`src/bh/cards/` reste). La doctrine ne fait que les nommer.
- **File de surface** : le runner ajoute au board les endpoints trouvés et pas encore testés (testé = touché par un
  `curl` autorisé ou un builtin de test).
- Métrique par run : commandes arsenal / manuelles / verrouillées (`runs.arsenal_calls` …).

### 6. `runner/` — superviseur autonome
- Une boucle : choisir un programme (priorité, temps déjà passé, dernier progrès) → lancer `claude -p` avec le contexte du board → suivre le flux `stream-json`.
- **Rotation** si : aucun nouveau fait depuis N tours, durée T dépassée, budget de tokens épuisé, ou refus répétés.
- **Limite Pro atteinte** : sauvegarde de la session, sommeil jusqu'au reset, reprise.
- Reflector : message système explicite (« pas d'appel d'outil depuis N tours : choisis une intention du board ou rends la main »), jamais dans la voix de l'utilisateur.

### 7. `verify/` — vérificateur
Conteneur `bh-judge` à lui, contexte neuf. Étage A : rejeu déterministe de la preuve (lectures deux fois, écritures une fois ; étapes navigateur jugées sur le `summary.json` de `bh-browse`, jamais sur un texte qui contient l'URL). Étage B : session Opus, escalade unique vers Mythos si `inconclusive`. Les champs écrits par le chasseur arrivent dans son prompt comme données balisées, bornées, sur une ligne. Contrôle qui répond comme l'attaque : `needs-proof` (le chasseur refait sa preuve, une fois). Rejeu refusé par le gate ou hôte en pause : le finding repasse `new`. Seul `verified` crée la todo `submit`.
Il tourne dans le conteneur `bh-judge` (service compose `judge`, démarré par `bh up`) : même image et même gate que
l'agent, mais son propre `/work` (`var/judge` sur l'hôte), qui ne voit pas celui du chasseur (`var/work`). L'hôte y
pousse la preuve et le prompt (`stack.push_file(..., container=JUDGE_CTR)`) et relit le verdict dans `var/judge`.
Juge arrêté : la vérification est remise à plus tard (statut `new` inchangé, aucune erreur comptée).

### 8. Pas d'humain pendant la chasse (2026-11-25)
Mio n'intervient qu'**après le triage**, pour soumettre. Pendant un run, aucun composant n'attend un humain.
Détail et audit : `research/11-autonomie-sans-humain.md`.

Todo humaine (post-triage) :
| Type | Déclencheur | Action humaine |
|---|---|---|
| `submit` | finding vérifié par le juge (Opus, ou Mythos en escalade) | Relire la PoC, soumettre |

Blocages pendant la chasse : fait `blocker` (`[raison] quoi`, montré 7 jours dans la frontière, `bh blockers`, onglet « Pistes bloquées ») :
| Blocage | Traitement autonome |
|---|---|
| challenge WAF répété | le gate met l'hôte en pause 1 h (3 challenges en 10 min, règle `waf-cooldown`) ; ses endpoints sortent de la surface non testée |
| session expirée | le gate émet `session-dead` sur redirection vers `login_url`, sonde ratée, ou 401 sur 3 routes distinctes en 10 min (un 401 isolé sous identité est un refus d'accès, jamais une mort) ; l'hôte sonde avant chaque segment, relance le login par recette (`bh accounts`), et retire l'identité du prompt et du juge tant qu'elle est morte |
| mur de login sans identité, 2ᵉ compte manquant | blocker `auth` / `account` ; comptes créés par l'hôte (à venir, issue 25) |
| captcha, SMS, KYC, fonction payante, écriture sur un tiers, hors bande | blocker `captcha` / `sms` / `kyc` / `paid` / `write-needed` / `oob-needed` ; jamais de résolution de captcha |
| actif hors scope | fait `out-of-scope` ; jamais d'élargissement |
| refus du modèle | blocker `refusal` ; 1ᵉʳ refus : pause 6 h ; 2ᵉ dans la chasse : programme parqué ; 3 en 7 jours : exclu au préflight |
| programme non prêt (`automation_allowed`, `scanners_allowed` inconnus) | exclu au préflight ; l'onboarding reste humain, hors chasse (autorisation légale) |
| juge `inconclusive` | escalade unique vers Mythos ; s'il reste `inconclusive`, statut visible dans Findings, sans todo |

### 9. `notify/`
Abandonné le 2026-11-25 (Gmail / Pub/Sub). La mise à jour des scopes sera déclenchée par un hook d'un autre type, le moment venu.

### 10. `ui/`
Vue en direct du flux de l'agent, board, findings + PoC (requêtes HAR rejouables en `curl`), todo de soumission, pistes bloquées, identités. Écoute sur l'IP Tailscale (ou `127.0.0.1`), jamais `0.0.0.0` ; connexion par token (`secrets/ui.token`) puis cookie HttpOnly ; CSP stricte, rendu `textContent` uniquement.

### 11. `bh` — CLI orchestrateur
`bh scope add|sync|diff|check <url>` · `bh run [--program X] [--once]` · `bh todo [done <id>]` (soumissions) · `bh blockers [programme] [--since H]` · `bh finding ls|show|verify` · `bh target local <url>` (cible perso : scope généré, en-têtes vides, débit libre) · `bh tokens calibrate|mine` (veille, alias abandonnés) · `bh ui`.
C'est l'interface par laquelle Claude (cette session) pilote le harnais.

## Blocs livrés en W1 à W3

Une section par bloc, quinze lignes au plus, chacune renvoie à son code. Schémas : `docs/diagrams.md`.

### Auto-test du gate (T4)
`src/bh/runner/preflight.py` : avant le premier segment de `bh run` et de `bh hunt`, la suite d'évasion
`tests/escape/escape_check.sh` tourne depuis le conteneur agent (`BH_ESC_JSONL=1`, une ligne JSON par contrôle). Profil
`lab` sur le scope du lab (refus, contrôles positifs et témoin), puis profil `msrc` sur le scope réel quand il a un hôte
passthrough (refus seulement). Prérequis : le lab tourne, aucun run actif. Un contrôle raté, une ligne illisible ou un
résumé absent annulent : pas de mode dégradé. `BH_PREFLIGHT=0` ne vaut que pour un programme `platform: local`.
`bh hunt` le fait une fois par programme et le transmet (`src/bh/runner/run.py`, `run_segment`). `arsenal()` vérifie
avant chaque segment que le binaire de chaque builtin est dans l'image ; il n'annule rien, il retire l'outil manquant de
l'Arsenal du system prompt. Résultat gardé dans `runs.preflight`.

### URL protégées (T5)
`src/bh/gate/policy.py` (`PROTECTED_DEFAULT`, `protected_rule`, `Policy.protected`) : un chemin de déconnexion, de
mot de passe, de suppression ou fermeture de compte, de paiement ou d'abonnement est refusé à tout client, bh-browser
compris, quelle que soit la méthode (« protected url »). Comparé sans casse sur le chemin seul (jamais la query), brut et
normalisé (`%xx` décodé, `;params` retirés, `//` réduits). Le scope en ajoute par `protected_urls`, n'en retire jamais.
Le contrôle passe juste après le chargement du scope, avant la garde de destinataires (`classify_request`).

### Garde de destinataires (D31)
`src/bh/gate/recipients.py` : une requête dont l'URL correspond à une entrée `recipient_guard` du scope (une route qui
porte un destinataire, invitation ou envoi) doit nommer au moins une adresse, et chaque adresse doit être celle d'une
identité du programme ; sinon « recipient not ours », quel que soit le client et la classe d'hôte. Refus aussi : un
destinataire nommé par un id, un corps illisible (compressé, trop long, multipart défectueux), aucune liste. La liste
`<state>/recipients.json` ne contient que des empreintes SHA-256, écrites par l'hôte depuis `secrets/` avant le segment
(`src/bh/runner/run.py`, `write_recipients`). Aucune option ne la desserre. `scopes/msrc/onedrive.yaml` l'active.

### Hôtes de charge (D27, O28)
`payload_hosts` du scope (`src/bh/scope/model.py`), jugés par `src/bh/gate/policy.py` (`is_payload`, `_payload_request`,
`check_ip`) : des hôtes sans données que le chasseur peut citer et charger (CORS, redirection, image) sans toucher un
tiers réel. GET, HEAD et OPTIONS sans corps, ports 80 et 443, IP publiques jamais nommées par une règle du scope ; ni
cookie, ni identité, ni en-tête de programme ; seau propre au débit du programme ; une ligne `class: payload` par
requête, jamais un test. Le scope refuse un hôte de charge qui serait une cible, un sous-domaine de cible ou un support.
Les skills écrivent `<payload-host>` et renvoient au bloc de scope ; aucun listé : `bh-note blocked other`.

### Règles du programme (S8, `bh rules`)
`src/bh/rules.py` : `bh rules check <scope>` lit chaque `rules_url` (GET simple, sans cookie ni en-tête de programme),
garde le texte visible sous `var/rules/<programme>/<date UTC>.txt` avec son SHA-256 et compare à la lecture d'avant ; un
changement ouvre une todo `rules-changed`. `bh rules ack <programme>` l'acquitte, `bh rules diff` montre l'écart.
`fresh()` : chaque page lue depuis moins de `FRESH_DAYS` (7) jours, aucun changement non acquitté. Le superviseur exclut
un programme qui ne l'est pas (`src/bh/runner/supervisor.py`, `rules_fresh`, en échec fermé). Rien de ce qu'une page
dit ne change le scope ni une garde : un humain lit le diff. Hôte seul, jamais monté dans un conteneur.

### Sessions et plafonds (D25)
`src/bh/runner/supervisor.py` : sur un programme réel, une chasse est une session de `RUNS_PER_SESSION` (11) runs dans
une phase nommée (`bh hunt --phase NOM`), `SESSIONS_PER_DAY` (3) sessions et `MAX_RUNS_PER_DAY` (33) runs par jour
(un `bh run` seul compris), `RUNS_PER_PHASE` (33) runs par phase. `admit()`, appelé par `run_segment` sous le verrou,
refuse avec la raison : un plafond n'attend jamais, ne reporte rien, et aucune option ni variable ne le relève.
`--runs` ne peut que l'abaisser. Les programmes `platform: local` (lab) ne comptent dans aucun. Le budget de prompts de
bh-browser se répartit sur les runs restants du jour (`prompt_allotment`, R44).

### Lignée et mémoire (W2)
`src/bh/lineage/`, hôte seul, jamais monté : chaque session `claude -p` est un agent numéroté (`identity.birth`,
pseudo, parent, condensat de naissance), qui naît du setup haché du segment (`src/bh/runner/identity.py`) et se clôt
en fin de segment ou à une rotation (`src/bh/runner/lineage_hooks.py`). Ses notes deviennent des items de mémoire
(`store.py` : `mem_items` sous une clé canonique `key.py`, plein texte FTS5, étiquette posée par l'hôte `OBSERVED`,
`JUDGED`, `ANCHORED` ou `NOTE`, datés puis remplacés, jamais effacés). Le successeur reçoit le bloc `## Lineage` de sa
tâche (`block.py`, 60 lignes au plus) et interroge `bh-recall` (`src/bh/agent/recall.py` dans la sandbox, réponse
écrite par le thread `serve.py` du runner, bornée par `recall.py`, avec un reçu `R-<id>`). La trace de chaque agent et
les blocs qui relient les agents d'un programme forment une chaîne de hash (`chain.py`) ; `score.py` tient le registre
de crédit (`ledger`), compté sur ce que l'hôte a vérifié ; `archive.py` écrit l'archive caviardée sous `var/lineage/`.
Toute requête filtre par programme. Commandes : `bh agent`, `bh memory`, `bh lineage`.

### Skills et MCP (W3)
Skills : `src/bh/skills/<nom>/SKILL.md` (frontmatter `name`, `description` de 200 caractères au plus, `requires:
scanners` éventuel), lues par `src/bh/classes.py` (`all_skills`) sans liste en dur. Le runner lie dans le HOME neuf de la
session toutes celles que le programme permet (`allowed_skills` : sans scanners, celles qui en exigent sont retirées ;
`link_skills`) ; la tâche nomme celles du programme (`cards` du scope) et donne en entier celles épinglées pour un
modèle (`pin_for_models`). Le juge n'en reçoit aucune. MCP : deux serveurs stdio dans la sandbox,
`bh-agent mcp bh` (`src/bh/agent/mcp/`, 12 outils) et `bh-agent mcp hexstrike` (`src/bh/agent/hexstrike/`, 3
méta-outils) ; chaque appel `mcp__*` passe par le hook PreToolUse et la table de `src/bh/agent/mcp_policy.py` (§5).
Un skill est une méthode, jamais une source de périmètre : le scope et le gate décident.

## Stack
Python 3.12 + `uv` (mitmproxy et les hooks sont en Python ; un seul langage). SQLite pour le board : un agent à la fois, pas besoin de Postgres.

## Risques
1. Tier Defense : refus sur l'exploitation. Mitigation : refus → blocker, abandon chiffré, et dossier Red Team.
2. Quota : plan Ultra depuis le 2026-11-24 (plus de fenêtre de 5 h). Mitigation conservée : Sonnet chasse, Opus juge, mesure du coût par finding vérifié.
3. API YesWeHack non documentée : peut casser. Mitigation : fallback `bounty-targets-data` + édition manuelle du YAML.
4. Gate HTTP seulement contournable par un outil qui ignore le proxy. Mitigation : l'agent n'a **aucune route** hors du réseau `sandbox`. Le gate est le seul chemin, pas une convention.

## Limites connues (après les deux revues hostiles du 2026-11-24)
- **Proxy du gate ouvert à ses réseaux** : `regular@8080` accepte tout client des réseaux du gate, donc aussi Juice
  Shop sur le réseau `lab`. Sans effet sur une cible réelle, qui n'est jamais sur nos réseaux ; le relais Anthropic, lui,
  n'accepte que l'agent et le juge. L'enrôlement des comptes passe volontairement par ce proxy depuis le gate (`127.0.0.1:8080`)
  pour subir la même politique que l'agent.
- **Session morte** : un 401 sous identité peut être un refus d'accès légitime (objet d'un autre). La marque « périmée »
  qu'il pose est levée au segment suivant si la sonde de l'identité (`probe`, avec contenu attendu) répond bien.
- **MCP** (W3) : la session de l'agent charge deux serveurs stdio, lancés dans le conteneur agent par
  `bh-agent mcp bh` (les builtins en 12 outils typés, `mcp__bh__*`) et `bh-agent mcp hexstrike` (trois méta-outils,
  `mcp__hexstrike__tools_list`, `tool_help`, `tool_run`) ; aucun autre serveur ne démarre, et l'agent voit 20 outils
  MCP au plus. Le juge n'en charge aucun (`--strict-mcp-config` sans `--mcp-config`) et son hook refuse tout outil
  `mcp__*`. Un `.mcp.json` laissé dans le dossier de travail est toujours effacé entre deux segments. Le hook
  PreToolUse couvre `Bash` et `mcp__.*` avec la même classification (§5) ; ce sont des aides, le gate reste la
  frontière : une requête lancée par un outil MCP passe par lui comme celle d'une commande `Bash`. Le relais ne
  change pas (paragraphe suivant).
- **Jeton OAuth** : n'existe que dans le gate ; l'agent a un jeton factice et `ANTHROPIC_BASE_URL=http://gate:8081`.
  Le relais n'accepte que les conteneurs agent et juge (résolus par nom, `BH_AGENT_HOST` / `BH_JUDGE_HOST`, cache
  60 s, une relecture DNS au plus toutes les 5 s pour une IP refusée ; le gate est aussi sur le réseau du lab, qui
  reste refusé), que les deux appels que fait
  Claude Code (`POST /v1/messages`, `/v1/messages/count_tokens`, mesuré sur 2.1.330), seulement pendant un run, et
  au plus `3 × max_turns + 30` requêtes par segment (plus un budget pendant la vérification). Il lit le corps :
  outils serveur (`web_search`, `web_fetch`…), `mcp_servers` (serveur MCP distant), sources URL et en-têtes
  `anthropic-beta` hors liste sont refusés (inchangé en W3 : les outils des serveurs stdio du sandbox arrivent au
  relais comme des outils client ordinaires), et chaque conteneur a sa liste de modèles (audit H1). Il journalise statut, id de message et
  `stop_reason` de chaque réponse, que le runner croise avant de croire un quota ou un refus. Reste : dans ce budget, un `claude -p` imbriqué consomme le
  quota (sans jeton à exfiltrer).
- **Le sandbox n'est pas une frontière** : hooks, verrou d'outils et fichiers du contrat sont des aides. Les garanties
  dures sont dans le gate (scope jugé sur le nom demandé, méthodes et overrides, identités existantes, ports web,
  énumération sur la route normalisée, garde scanners par rafale de 404, websockets refusés sauf opt-in du scope et
  bornés, hôtes de support hors test, débit) et sur l'hôte
  (ingestion typée, preuve revalidée, « testé » confirmé par le gate, secrets caviardés).
- **Exclusions** : une entrée YWH n'exclut une classe entière que si elle la nomme ; les exclusions conditionnelles
  restent à l'humain. Brute force interdit par la doctrine et, pour les programmes sans scanners, freiné par la garde
  404 du gate. Exclusions sans signature réseau (social engineering, physique) : doctrine seulement.
- **Vérificateur** : conteneur à lui (`bh-judge`, issue 3) : le chasseur ne voit ni son `/work`, ni ses process, ni
  son `/tmp`, et réciproquement ; même durcissement que l'agent, réseau `sandbox` seul, donc toujours derrière le gate
  (aucun nouveau chemin réseau). Dans ce conteneur : utilisateur Unix `judge`, tous ses process tués, HOME et
  fichiers temporaires effacés et dossier recréé avant chaque vérification ; `python3 -I`, modèle différent (Opus),
  verdict valable seulement avec le nonce donné au seul process du juge. Les process du chasseur sont encore tués
  avant le rejeu (pour l'état de la cible, plus pour l'isolation). Reste : le juge lit des réponses de la cible
  (injection de prompt possible, comme pour tout relecteur) ; il partage avec le chasseur l'image, le gate, le
  budget de relais du run et le code sandbox monté en lecture seule.
- **Énumération** : comptée sur les ids du chemin seulement (I6), route normalisée, au plus 6 ids distincts par route
  en 10 min (le 7e est refusé ; `policy.ID_LIMIT`, `policy.ID_WINDOW_S`). Un id passé en query string, en corps formulaire, JSON ou GraphQL n'est pas compté :
  la doctrine (preuve sur nos propres objets) et le juge couvrent ce cas.
- **bh-browser** : reconnu par son IP. Un autre conteneur qui reprendrait cette IP (bh-browser arrêté, IP réattribuée
  avant l'expiration du cache de 60 s) en hériterait : identité de la jarre, `browser_only`, méthodes d'identité. Le
  réseau `sandbox` est le nôtre et ses conteneurs sont fixes, mais rien ne le prouve au gate. Le fichier
  `browser-identity.json` est écrit par l'hôte (`browser_service/host.py`, dans `var/state`, que le sandbox ne monte
  pas) ; l'identité qu'il nomme dit
  *quelle jarre* reçoit les `Set-Cookie`, pas ce que le navigateur envoie vraiment : si l'opérateur change de compte
  dans le navigateur sans recharger, les flux sont mal étiquetés jusqu'au prochain chargement. Les cookies de
  bh-browser ne sont pas masqués : le chasseur peut les lire par bh-web s'il demande la page qui les affiche (c'est le
  navigateur de notre compte de test).
- **Canaris** : la recherche s'arrête à 2 Mio décodés par contenu et à 16 jetons distincts ; un jeton coupé entre deux
  trames websocket, encodé autrement (base64, %xx, échappement JSON `\u00..`) ou dans un tunnel passthrough n'est pas
  vu. Le juge de la fuite reste l'humain qui lit l'événement.
- **Sonde** : le marqueur n'est honoré que depuis la boucle locale du gate ; tout process du conteneur du gate peut
  donc emprunter une session, ce qui est déjà le cas de l'enrôlement (il y tourne avec les secrets).
- **Stockage** : fichiers de flux supprimés après 14 jours, journaux du gate tournés en gzip au-delà de 64 Mo
  (`bh prune`, et au début de chaque segment). Images épinglées par digest ; les paquets apt de Kali suivent le dépôt.
- **Coût du verrou sur une vraie cible** : crawl + content + scan par origine (~10 min chacun à 2 req/s).
- **nuclei** : ~1,5 req/s via le gate, cause interne non trouvée ; borné par `--timeout`.
- **Hôtes de support** : le contenu des `assets` n'est pas jugé (un CDN sert ce qu'on lui demande en GET) ; un chasseur
  peut y lire des fichiers publics, pas y écrire. La liste que lit `bh-browse` vient de `scope.yaml` dans `BH_DIR`,
  que le chasseur peut réécrire : sans effet, le gate juge sur son propre scope. Les cookies de `bh-login` posés sur
  un hôte `auth` hors des `goto` de la recette ne sont pas gardés dans la session (`enroll._host_ok`) ; ceux d'un hôte
  `sso` (et de ses domaines parents) le sont, et le gate ne les injecte que vers cet hôte.
- **sso** : un hôte `sso` est une page de connexion que le chasseur peut lire en GET (et en POST sur l'échange de
  jeton) ; il ne peut ni y soumettre un formulaire de login, ni y recevoir une valeur de cookie de nos comptes (masquée).
  Le jeton d'API obtenu par l'échange arrive en clair au navigateur de l'agent (c'est le fonctionnement de l'appli) :
  il est celui de notre compte de test et ne sort que vers les cibles et les hôtes `sso` (le gate). Un `OPTIONS` de
  pré-vol CORS vers le chemin de jeton serait refusé : à vérifier en live (MSAL l'évite en principe).
- **passthrough** : le gate ne voit pas l'intérieur du tunnel. Il contrôle l'émetteur (bh-browser seul), le nom du
  CONNECT, le SNI (via `ignore_hosts`), l'IP, le débit, les octets et la durée ; pas l'en-tête `Host` chiffré.
  bh-browser pourrait donc ouvrir un tunnel vers l'IP du challenge avec ce SNI et un autre `Host` : du domain
  fronting, que Cloudflare refuse en principe entre zones (non vérifié ici) ; le chasseur ne pilote bh-browser que par
  bh-web. Borné par la garde de tunnels et journalisé. Pas d'ECH : derrière un proxy HTTP, Chromium ne résout pas le
  DNS et n'envoie pas d'ECH. Un tunnel refusé est fermé par `close_connection` (internes de mitmproxy 12.3.1, à
  mesurer en live) et, à défaut, mis en trou noir (chaque message vidé). Un handshake websocket ne peut pas porter `X-BH-Identity` en injection par requête
  (Playwright ne route pas les en-têtes des websockets) : il part sans identité. Le challenge décide seul ; nous ne
  le résolvons, ne le contournons ni ne le testons jamais (`runner/prompt.py`, « Anti-bot challenges ») ; un humain
  peut le résoudre dans le navigateur persistant de l'agent.
- **Websockets** : le contenu des trames n'est pas jugé (pas de scope dans une trame, pas de garde d'énumération) ;
  seuls le volume, la taille et la durée sont bornés, et tout est journalisé (les canaris y sont cherchés). Fermeture
  d'une connexion muette à sa limite de durée : `close_connection` depuis un minuteur ; effet réel (le client et
  l'amont voient la connexion tomber) à mesurer en live sur la 12.3.1 ; à défaut, la prochaine trame, dans un sens
  ou l'autre, est abandonnée. Websocket sur HTTP/2 (CONNECT étendu) : méthode CONNECT
  refusée par la politique, donc refusé.
- **Rechargement du gate** : mitmdump recharge `addon.py` mais pas `policy.py` ; après une modification de la
  politique, `podman restart bh-gate` (en attendant, le gate refuse : fail-closed).
- Liste à jour des points ouverts : `docs/TODO.md`, section « Revue hostile du 2026-11-24 ».
