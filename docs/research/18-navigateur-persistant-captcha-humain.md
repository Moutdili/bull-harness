# 18 — Navigateur persistant, écran distant, challenge résolu par Mio (2026-11-25)

Agent P1 du swarm. But : que Mio résolve **lui-même** un challenge anti-bot (Cloudflare Turnstile) dans **le
navigateur que l'agent utilise**, puis rende la main. Code : `src/bh/browser_service/*`, `src/bh/ui/ws.py`,
`src/bh/ui/server.py` (`/captcha/`), `src/bh/cli.py` (`bh browser`), `container/compose.yaml` (service `browser`),
`container/agent/Containerfile` (étape 5c), `src/bh/agent/web.py` (`bh-web`, côté agent). Tests :
`tests/test_browser_service.py`, `tests/test_browser_controller.py`, `tests/test_browser_watch.py`,
`tests/test_ui_captcha.py`, `tests/agent/test_web.py`.

Statut : **construit et testé hors conteneur**, puis repris après l'audit Mythos (doc 19 : B1, B3, B4, I2, I3, I4,
I12, I17). Le contrat complet est au §7. Rien de ce document n'est encore mesuré en vrai : voir §6 et §7.8.

## 1. Ligne éthique

| Interdit (code + doctrine) | Comment c'est tenu |
|---|---|
| Navigateur déguisé | Chromium du paquet Kali, headful, lancé par nous avec ses réglages d'origine. Aucun `--user-agent`, `--disable-blink-features=AutomationControlled`, `--headless`, extension stealth. Test `test_chromium_is_not_disguised`. Playwright ne lance rien : il s'attache par CDP (`connect_over_cdp`). |
| Service de résolution | Aucun. Aucune requête ne quitte le conteneur hors du gate. |
| Clic automatisé sur le challenge | Tant qu'un challenge est détecté, `goto`, `click`, `fill`, `press` et `upload` de l'agent sont refusés (409 `human-needed`), avant d'atteindre la page. Test `test_the_agent_never_clicks_types_or_presses_on_a_challenge`. |
| Rejouer ou transférer un jeton | Le jeton reste dans le navigateur qui l'a obtenu. Ni l'agent ni l'hôte ne lisent cookies ou storage par l'API. |

Permis : **Mio** clique le challenge, à la main, dans l'écran de **ce** navigateur. Un jeton Turnstile est lié au
navigateur qui l'a obtenu. On lui montre donc l'écran du navigateur de l'agent, pas un lien à ouvrir chez lui.

Point à trancher par Mio : quand Playwright lance Chromium, il ajoute `--enable-automation`, ce qui met
`navigator.webdriver` à `true`. Ici Chromium est lancé sans ce flag, puisque Playwright ne fait que s'attacher. Avec
`--remote-debugging-port` seul, la valeur de `navigator.webdriver` n'est pas vérifiée : à mesurer au §6 (étape 4).
On ne la masque pas. On ne l'ajoute pas non plus, faute de règle qui l'exige. Si Mio veut que le navigateur se
déclare automatisé, il suffit d'ajouter `--enable-automation` dans `chromium_argv`. Turnstile refusera alors
probablement toute résolution.

## 2. Architecture

```
 Mio (navigateur, tailnet)
   │ HTTP + WebSocket, cookie de session de l'UI (jeton secrets/ui.token → cookie HttpOnly SameSite=Strict)
   ▼
 bh ui (hôte, IP Tailscale:7340)
   /captcha/            page + captcha.js (CSP propre à la page, sans inline)
   /captcha/novnc/...   client noVNC, lu une fois dans bh-browser (`podman exec ... tar -ch /usr/share/novnc`)
   /captcha/ws          WebSocket terminé par l'UI (même origine exigée) ──┐
   /api/captcha/status  /api/captcha/done                                  │ `podman exec -i bh-browser python3 -I -c PIPE`
                                                                          ▼ (octets RFB, stdin/stdout)
 ┌──────── bh-browser (réseau sandbox seulement, HTTPS_PROXY=gate:8080) ────────────────────────────┐
 │ Xvfb :99 ── Chromium headful (profil /profile, volume browser-profile, proxy gate:8080)          │
 │   │           └ CDP 127.0.0.1:9222 ── contrôleur (Playwright connect_over_cdp, un seul fil)       │
 │ x11vnc 127.0.0.1:5900 (-localhost)          ├─ API agent  :8790  POST /op, Bearer BH_BROWSER_TOKEN│
 │                                             └─ socket de contrôle /tmp/bh-browser/ctl.sock (0700) │
 └────────────────────────────────────────────────────────────────────────────────────────────────────┘
        ▲ http://browser:8790 (sandbox)                         ▲ `podman exec -i ... host` (JSON stdin)
   bh-agent (curl, BH_BROWSER_URL + BH_BROWSER_TOKEN)        hôte : bh browser load|status|reset
```

### Chemin réseau de l'écran : choix du tunnel `podman exec`

- Publier un port d'un conteneur du réseau `sandbox` n'a **pas été essayé**. Le réseau est `internal: true`, en
  netavark avec pasta. La consigne interdit de recréer un conteneur, et un essai aurait exigé un conteneur jetable.
- Un réseau dédié non `internal` aurait donné à bh-browser une route directe vers Internet, sans passer par le gate.
  Ce choix est exclu.
- Retenu : **aucun port publié et aucun réseau ajouté**. L'UI ouvre un `podman exec -i` par écran ouvert. Ce
  processus relie stdin/stdout à `127.0.0.1:5900` dans le conteneur. C'est le même mécanisme que `bh-login`.
- Pas de websockify : l'UI termine elle-même la WebSocket (`src/bh/ui/ws.py`, RFC 6455 minimal). x11vnc ne parle
  que RFB brut sur la boucle locale du conteneur, qu'aucune page web ne peut parler. Un websockify en TCP aurait
  ouvert l'écran, sans mot de passe, à toute page chargée dans ce même Chromium. Le paquet `websockify` est installé
  comme dépendance de `novnc`, mais il ne tourne pas.
- x11vnc tourne sans mot de passe. La seule voie vers lui passe par `podman exec`, donc par l'hôte, donc derrière la
  session de l'UI.

### Surface de l'UI

- Toutes les routes `/captcha/*` passent par le `_authed()` existant. Sans cookie de session, la réponse est la page
  de login (401) et aucun tunnel n'est ouvert (test `test_captcha_pages_need_the_ui_session`).
- WebSocket : en plus du cookie, l'en-tête `Origin` doit être celui de l'UI, contre le détournement de WebSocket
  inter-sites. Au plus 2 écrans à la fois.
- Jeton (B1) : le cookie de session est un HMAC du jeton `secrets/ui.token`. `rotate_token()` le remplace
  (0600, renommage atomique) ; l'UI qui tourne relit le fichier quand il change (`UIServer.token`), donc toutes les
  sessions meurent sans redémarrage (test `test_rotation_reaches_the_running_ui_and_kills_old_sessions`).
- CSP de `/captcha/` seulement : `default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`.
  Le reste de l'UI garde sa CSP.
- « J'ai fini » : `POST /api/captcha/done` (cookie + `X-BH: 1`, comme les autres POST). L'UI écrit
  `var/browser/captcha-done.json` (`{"t": ...}`), que l'hôte lit. Elle appelle aussi `human_done` dans le contrôleur.
  L'agent voit alors `human_done_at` dans `state()`. S'il ne reste aucun challenge, l'écran passe en **spectateur**
  (noVNC en lecture seule, l'agent reprend sous les yeux de l'opérateur) ; s'il en reste un, rien ne change (§7.2).

### API de l'agent et interface de l'hôte

Voir le contrat complet au §7 (ops, champs de `state()`, fichiers, budgets, reprise).

`bh browser load <scope.yaml> <identité>` lit `var/state/identities/<prog>/<nom>.json` avec `bh.gate.session.load`.
Il en tire les cookies de la jarre : un cookie host-only est posé par URL, un cookie de domaine par `.domaine`. Les
en-têtes, comme `Authorization`, ne sont **pas** injectés : un navigateur envoie les siens. Ils sont nommés à
l'écran.

## 3. Flux complet

1. Avant le segment, l'hôte prépare le profil (`watch.prepare`) : une seule identité vivante, budget de segment remis
   à zéro (§7.5).
2. L'agent pilote bh-browser par `bh-web` (`goto`, `fill`, `click`…) et lit `bh-web state`.
3. `state().challenge.pending == true`. Toute action sur la page est refusée (409 `human-needed`, `bh-web` sort en
   code 3). L'agent lance `bh-web wait-human`, qui ne fait que relire `state()`.
4. L'hôte (`watch.ChallengeWatcher`, toutes les 10 s) voit le challenge et pousse une notification ntfy à Mio : au
   plus une toutes les 5 min, un seul rappel 10 min après, rien de plus pour ce challenge.
5. Mio ouvre `http://<ip-tailscale>:7340/captcha/`, se connecte à l'UI si besoin. Tant que l'écran est ouvert,
   l'agent ne peut que lire (`human_viewing`, §7.2). Mio résout le challenge à la main, puis clique « J'ai fini » :
   l'écran passe en spectateur (`human_watching`), Mio regarde, l'agent reprend.
6. La reprise (§7.6) : `wait-human` rend 0 quand `pending` repasse à `false` **et** que l'écran est rendu
   (`human_viewing` faux : spectateur ou écran fermé), et dit à l'agent de vérifier que son message est parti. Si le
   challenge reste au-delà de 300 s, `wait-human` rend 3 : l'agent note `bh-note blocked captcha` et passe à une
   autre surface. Challenge parti mais écran encore en main au bout de 300 s : `wait-human` rend 3 aussi, et dit de
   relire `bh-web state` plus tard.

## 4. Mise en service (orchestrateur)

```
podman build -t localhost/bh-agent:dev container/agent   # étape 5c : xvfb, x11vnc, novnc
bh up                                                     # crée secrets/browser.env ; agent recréé avec BH_BROWSER_*
podman-compose -f container/compose.yaml up -d --no-deps --force-recreate agent   # si l'agent tournait déjà
bh browser up                                             # --profile browser up -d --no-deps browser
bh browser status
podman logs bh-browser | tail
```

Rappel (leçon du 2026-11-24) : toujours `--no-deps <service>` pour un `--force-recreate`.

## 5. Procédure d'essai live avec Mio (Copilot, compte gratuit)

Prérequis : scope `scopes/msrc/copilot.yaml` à jour (lot N1). Le gate doit laisser passer
`challenges.cloudflare.com` vers le navigateur : c'est à vérifier dans la politique du gate, sinon le widget ne se
charge pas.

1. `bh browser up`, puis `bh browser status` → `challenge none`, URL `about:blank`.
2. `bh browser load scopes/msrc/copilot.yaml <identité>` → nombre de cookies chargés. Sans session, Mio peut se
   connecter à la main dans l'écran : le profil persiste.
3. Mio ouvre `bh browser view`, se connecte à l'UI, voit l'écran.
4. Mesure de l'honnêteté du navigateur. Dans l'écran, Mio ouvre un onglet sur une page en scope et note la valeur
   de `navigator.webdriver`. On ne l'évalue pas depuis l'API, qui ne le permet pas. Mio peut la lire avec DevTools
   s'il le souhaite. Valeur à consigner ici.
5. Depuis l'agent (ou à la main, par curl dans bh-agent) : `goto` vers Copilot, `fill` du message, puis `click` sur
   Envoyer.
6. Attendu : `state().challenge.pending == true`, et `click` rend 409. Sinon, consigner : pas de challenge pour ce
   compte ou cette session.
7. Mio résout le challenge dans `/captcha/`, puis clique « J'ai fini ».
8. L'agent rappelle `state()`, puis `click` sur Envoyer. **Mesure** : le message part-il ? Consigner pour chaque
   essai le statut, l'heure, et s'il y a eu un deuxième challenge (`TurnstileOneChallengeInAppSession` laisse
   attendre au plus un challenge par session d'appli).
9. Répéter après `bh browser down` / `up` : le profil persiste. Un nouveau challenge apparaît-il ?

Critère binaire : un message envoyé après une résolution humaine, sans aucune action automatisée sur le challenge.

## 6. Limites et incertitudes

- **Cloudflare peut refuser malgré une résolution correcte.** Le score Turnstile tient aussi compte du navigateur :
  CDP actif, Xvfb, absence de GPU, `--no-sandbox`, IP de sortie, proxy qui intercepte TLS (le gate, mitmproxy, donc
  une empreinte TLS qui n'est pas celle de Chromium). Un refus est un résultat. On ne cherche pas à le contourner.
- Rien n'a tourné en conteneur. Points à vérifier au premier lancement :
  - les versions Kali épinglées (étape 5c) : un dépôt rolling qui a bougé fait échouer le build ;
  - la présence de `/usr/share/novnc/core/rfb.js` (vérifiée au build) ;
  - les imports de `vendor/pako` dans le paquet Debian : `tar -h` suit les liens symboliques, mais si Debian a
    réécrit les chemins d'import, l'écran ne se charge pas.
- `connect_over_cdp` entre Playwright 1.65.2 et le Chromium Kali (version notée dans `/opt/bh/browser-versions.txt`)
  : la compatibilité CDP est à vérifier.
- `--no-sandbox` est nécessaire, comme pour bh-login : le conteneur durci ne donne pas de namespaces utilisateur.
  Chromium affiche alors un bandeau d'avertissement.
- Le WebSocket noVNC n'a été testé qu'avec un tunnel `cat` (test `test_websocket_relays_bytes_both_ways`), pas
  avec x11vnc ni avec le vrai client noVNC.
- Les cookies injectés sont posés sans `HttpOnly`, faute de cette information dans la jarre du gate. Les en-têtes
  d'identité ne sont pas injectés.
- Le profil du navigateur est un état persistant de l'agent, partagé entre les segments. `bh browser reset --yes`
  l'efface.
- La fixture `tests/fixtures/copilot_verification_required.html` est **reconstruite** d'après l'observation du
  2026-11-25/26, pas enregistrée. Voir §7.7 pour la remplacer par un vrai instantané.

## 7. Contrat complet (après l'audit 19)

Source de vérité : `src/bh/browser_service/__init__.py` (`AGENT_OPS`, `HOST_OPS`, `VIEWING_OPS`) et `SPEC` dans
`controller.py`. Tout champ inconnu, toute op hors de la liste de la porte appelée, toute valeur hors bornes : 400.

### 7.1 Ops de l'agent (`POST http://browser:8790/op`, `Authorization: Bearer $BH_BROWSER_TOKEN`, via `bh-web`)

| op | `bh-web` | champs | réponse | challenge | écran ouvert |
|---|---|---|---|---|---|
| `goto` | `goto <url>` | `url` http(s), ≤ 2000, pas le conteneur lui-même | état | refusé | refusé |
| `fill` | `fill <css> <texte>` | `css` ≤ 300, `text` ≤ 2000 | `{ok, fills}` | refusé | refusé |
| `click` | `click <css>` | `css` | état | refusé | refusé |
| `press` | `press <touche>` | `key` ∈ Enter, Tab, Shift+Tab, Escape, Backspace, Delete, Space, flèches, Home, End, PageUp, PageDown | état | refusé | refusé |
| `upload` | `upload <css> <fichier>` | `css`, `name` (sans chemin), `content_b64` (≤ 256 Kio décodés) | `{ok, name, bytes, mime}` | refusé | refusé |
| `wait` | `wait <css\|ms>` | `css` **ou** `ms` ≤ 30000 | état | permis | refusé |
| `outline` | `outline [--css C]` | `css` | `{outline ≤ 12000, truncated}` | permis | refusé |
| `attr` | `attr <css> <nom>` | `css`, `name` | `{name, value ≤ 4000, truncated}` | permis | refusé |
| `net` | `net [--last N] [--denied]` | `last` 1–200, `denied` | `{requests: [{t, method, url caviardée, status, denied, reason, failure}], count}` | permis | refusé |
| `tabs` | `tabs [--select I]` | `select` 0–50 | `{current, tabs: [{i, url, title}]}` | permis | refusé |
| `switch` | `switch <identité>` | `identity` | `{ok, switch_requested, note}` | permis | refusé |
| `state` | `state` | — | état (§7.3) | permis | **permis** |
| `text` | `text [--css C] [--tail N]` | `css`, `tail` 1–20000 | `{text ≤ 8000 (tête) ou N (queue), truncated, length, from}` | permis | **permis** |
| `frames` | `frames [--last N]` | `last` 1–200 | `{frames: [{t, dir, url, text}], count}` | permis | **permis** |

- « challenge » : refusé = 409 `human-needed` (`bh-web` sort en 3). La vérification passe avant la page : rien
  n'atteint le challenge. `goto` est refusé aussi : naviguer perdrait le challenge et le message tapé dessous.
- « écran ouvert » : tant que l'opérateur a `/captcha/` ouvert et en main (`human_viewing`), seules `state`, `text`
  et `frames` répondent ; le reste rend 409 `human-viewing` (`bh-web` sort en 3). Un écran spectateur
  (`human_watching`, §7.2) ne compte pas : l'agent y a toutes ses ops.
- `fill` au-delà du budget : 429 `fill-budget` (`bh-web` sort en 4).
- `switch` ne bascule rien lui-même : il pose `switch_requested`, que l'hôte exécute (§7.5). Coût affiché par
  `bh-web` : un nouveau profil, donc une nouvelle session d'appli, donc **un challenge de plus par bascule**.
- `bh-web wait-human [--timeout S]` n'est pas une op : il relit `state` toutes les 10 s (timeout d'un appel 15 s)
  pendant au plus 300 s, et attend le challenge **et** l'écran : il ne rend 0 que si `challenge.pending` et
  `human_viewing` sont faux tous les deux. Pire cas 315 s, sous les 330 s de `BASH_DEFAULT_TIMEOUT_MS` du runner (test
  `test_wait_human_ends_before_the_bash_tool_timeout`).
- Jamais : cookies, storage, en-têtes, CDP brut, évaluation de script, capture d'écran. `frames` ne garde aucune
  trame qui nomme un challenge (`ChallengeProof`, `turnstile`, `cf-chl`, `cf_clearance`) ; dans les autres, toute
  valeur de clé contenant `token` est remplacée. Chaque réponse est caviardée : valeurs de la session chargée,
  cookies vivants du navigateur (≥ 8 caractères), JWT, paramètres sensibles des URL.

### 7.2 Ops de l'hôte (`podman exec -i bh-browser python3 -I -c BOOT host`, une ligne JSON sur stdin)

| op | champs | effet |
|---|---|---|
| `load_session` | `program`, `identity`, `cookies`, `secrets` | pose les cookies, écrit le marqueur ; 409 si le profil tient une autre identité |
| `status` | — | état (§7.3) + `cookies_loaded` |
| `reset` | `force` (bool) | supprime le marqueur puis efface le profil ; sans `force`, 409 si un challenge est à l'écran ; met fin au mode spectateur |
| `human_done` | — | `human_done_at` = maintenant (« J'ai fini » de l'UI) ; sans challenge à l'écran, passe en spectateur ; rend `{ok, human_done_at, watching, challenge_pending}` |
| `human_viewing` | `on` (bool) | `on` : écran ouvert pendant 600 s (`VIEWING_TTL_S`), l'agent ne fait que lire sauf en spectateur ; `off` : fin, et fin du mode spectateur |
| `fill_budget_reset` | — | remet à zéro le compteur du segment (pas celui du jour) |
| `switch_refused` | `identity`, `reason` (≤ 200) | efface `switch_requested`, pose `switch_error` |
| `snapshot` | — | ce que `detect.challenge()` lit de la page, et son verdict (§7.7) |

- L'UI envoie `human_viewing on` à l'ouverture de chaque écran `/captcha/ws`, le répète toutes les 240 s tant qu'il
  reste ouvert, et envoie `off` quand le dernier écran se ferme (compteur d'écrans, au plus 2). Les envois passent
  sous un verrou : un `on` tardif d'un écran fermé n'arrive jamais après le `off`. Si l'UI meurt sans `off`, le
  contrôleur l'oublie après 600 s. Tests `test_an_open_screen_tells_human_viewing_on_then_off_when_the_last_one_closes`
  et `test_the_screen_re_asserts_human_viewing_while_open_and_stops_once_closed`.
- **Mode spectateur** (depuis `f5fc067`, `controller.py` `_op_human_done`, `_op_human_viewing`, `_state_dict`) :
  - « J'ai fini » sans challenge restant : `human_viewing` faux, `human_watching` vrai. L'écran `/captcha/` passe
    noVNC en lecture seule (`viewOnly`, étiquette « spectateur : l'agent travaille ») : l'opérateur regarde, aucun
    clic ni aucune touche n'atteint le navigateur, et l'agent reprend avec toutes ses ops.
  - Un clic sur « J'ai fini » pendant que le challenge est encore là ne change rien : l'écran reste en main, seul
    `human_done_at` est noté, et le bouton affiche « Le challenge est encore là ».
  - Rendent la main à l'opérateur : un nouveau challenge (vu au prochain `state` ou `status`, que l'écran relit en
    continu), un `reset`, ou la fermeture du dernier écran (`human_viewing off`) ; l'écran ouvert ensuite est de
    nouveau en main.
- L'agent ne peut demander aucune op de l'hôte (`AGENT_OPS ∩ HOST_OPS = ∅`, test
  `test_every_agent_op_has_a_command_and_no_host_op_does`).

### 7.3 Champs de `state()`

| champ | sens |
|---|---|
| `url`, `title` | page pilotée, URL caviardée, titre ≤ 200 |
| `challenge` | `{pending, reason, since, cleared_at}` : `since` = début du challenge en cours, `cleared_at` = fin du dernier |
| `human_done_at` | dernier « J'ai fini » de l'opérateur, ou `null` |
| `human_viewing` | l'opérateur a l'écran ouvert **et en main** : l'agent ne fait que lire (faux en spectateur) |
| `human_watching` | l'écran est ouvert en spectateur, après « J'ai fini » sans challenge restant : l'agent travaille |
| `identity`, `program` | lus dans le marqueur du profil (`null` si profil vide, `"?"` si illisible) |
| `switch_requested`, `switch_error` | bascule demandée par l'agent et pas encore faite ; raison du dernier refus |
| `fills` | `{segment_left, day_left}` |
| `tabs` | `{count, current}` (si le pilote les donne) |

Détection (`detect.challenge`) : en attente si une frame de `challenges.cloudflare.com` est visible ou de
visibilité inconnue (on échoue fermé), ou si le texte nomme une vérification humaine (« Security check »,
« Verify you are human », « Verification required », leurs équivalents français) **et** que c'est crédible : une
frame de challenge existe (même cachée), ou le titre est celui d'une interstitielle, ou la page fait moins de 600
caractères. Une conversation qui cite « security check » n'est pas un challenge.

### 7.4 Fichiers

| fichier | écrit par | contenu |
|---|---|---|
| `/profile/bh-identity.json` (volume `browser-profile`) | contrôleur, `load_session` ; supprimé par `reset` | `{program, identity, loaded_at}` : le compte que tient le profil, survit au redémarrage du conteneur |
| `/profile/bh-fills.json` | contrôleur, à chaque `fill` | `{segment, days: {<identité>: {day (UTC), n}}}` ; survit à un `reset` |
| `<state>/browser-identity.json` | hôte, après chaque `load`, `switch` et `reset` réussis (écriture atomique, 0644) | `{program, identity \| null, loaded_at}` ; lu par le gate pour étiqueter le trafic de bh-browser (contrat fixe) |
| `var/browser/captcha-done.json` | UI, « J'ai fini » | `{t}` |
| `var/browser/snapshot-<heure>.json` | hôte, `host.save_snapshot()` (0600) | §7.7 |

### 7.5 Budgets et identités

- `fill` : **80 par segment** (remis à zéro par `prepare` via `fill_budget_reset`) et **200 par identité et par jour
  UTC** (persistant, un `reset` ne l'efface pas). Un `fill` refusé ne consomme rien.
- Une seule identité par profil. `prepare` garde l'identité en place si elle est encore vivante pour ce programme
  (sa clairance de challenge survit), sinon `reset force` puis charge la première identité vivante.
- `switch` : le watcher de l'hôte l'exécute (`reset` puis `load`) seulement pour une identité vivante du programme
  préparé, jamais pendant un challenge (il attend) ; sinon `switch_refused` avec la raison.

### 7.6 Reprise après captcha

Un message tapé sous un challenge part tout seul quand l'opérateur passe le challenge. `wait-human` rend 0 avec
`{challenge: "cleared", url, cleared_at, human_done_at}` et écrit sur stderr : vérifier par
`bh-web text --tail 2000` que le message est parti, n'appuyer sur Entrée qu'une fois sinon, puis reprendre
l'intention en cours. D'où le refus de `goto` pendant le challenge : il perdrait ce message.

### 7.7 Remplacer la fixture reconstruite par un vrai instantané

L'op d'hôte `snapshot` rend ce que le pilote lit pour la détection (`url`, `title`, texte visible en tête et en
queue, `text_len`, frames avec leur visibilité), avec le verdict de `detect.challenge()`. **Jamais le HTML** : pas
de champ caché (la réponse Turnstile), pas de script, pas d'attribut. Réponse caviardée comme toutes les autres.
Procédure, la prochaine fois que « Verification required » est à l'écran :

```
uv run python -c "from bh.browser_service import host; print(host.save_snapshot())"
```

Le fichier `var/browser/snapshot-<heure>.json` (0600) contient le texte de la conversation : le relire et retirer
tout contenu personnel avant de le copier sous `tests/fixtures/`. Ensuite un test charge `saved["snapshot"]` et
vérifie `challenge(...) == saved["challenge"]` (modèle : `test_snapshot_is_what_detect_reads_scrubbed_and_feeds_challenge_back`).
Pas de commande `bh browser snapshot` : la CLI appartient à un autre lot.

### 7.8 Mesures live encore à faire

1. Détection sur le vrai Copilot : `snapshot` pendant un « Verification required », `pending == true`, raison notée.
2. Visibilité de l'iframe Turnstile vue par Playwright (`frame_element().is_visible()`) : vrai, faux, ou inconnu.
3. Reprise : après résolution, le message part-il seul, ou faut-il Entrée ? Un second challenge dans la même
   session d'appli ?
4. `human_viewing` : 409 `human-viewing` pour un `click` quand `/captcha/` est ouvert, retour à la normale à la
   fermeture, et passage en spectateur (`human_watching`) après « J'ai fini » ; coût réel d'un `podman exec`
   (latence avant l'affichage de l'écran).
5. `switch` de bout en bout : délai réel (annoncé ~10 s), nouveau challenge, `browser-identity.json` lu par le gate.
6. `frames` sur le hub SignalR de Copilot : aucune trame `ChallengeProof` gardée, réponses lisibles.
7. `upload` d'un fichier dans le composeur Copilot, sans sélecteur de fichier.
8. `navigator.webdriver` (§5 étape 4) et compatibilité CDP Playwright 1.65.2 / Chromium Kali (§6).
