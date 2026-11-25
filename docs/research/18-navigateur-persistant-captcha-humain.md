# 18 — Navigateur persistant, écran distant, challenge résolu par Mio (2026-11-25)

Agent P1 du swarm. But : que Mio résolve **lui-même** un challenge anti-bot (Cloudflare Turnstile) dans **le
navigateur que l'agent utilise**, puis rende la main. Code : `src/bh/browser_service/*`, `src/bh/ui/ws.py`,
`src/bh/ui/server.py` (`/captcha/`), `src/bh/cli.py` (`bh browser`), `container/compose.yaml` (service `browser`),
`container/agent/Containerfile` (étape 5c). Tests : `tests/test_browser_service.py`, `tests/test_ui_captcha.py`.

Statut : **construit et testé hors conteneur**. L'image n'a pas été reconstruite et aucun conteneur n'a été lancé.
Rien de ce document n'est encore mesuré en vrai : voir §6.

## 1. Ligne éthique

| Interdit (code + doctrine) | Comment c'est tenu |
|---|---|
| Navigateur déguisé | Chromium du paquet Kali, headful, lancé par nous avec ses réglages d'origine. Aucun `--user-agent`, `--disable-blink-features=AutomationControlled`, `--headless`, extension stealth. Test `test_chromium_is_not_disguised`. Playwright ne lance rien : il s'attache par CDP (`connect_over_cdp`). |
| Service de résolution | Aucun. Aucune requête ne quitte le conteneur hors du gate. |
| Clic automatisé sur le challenge | Tant qu'un challenge est détecté, `click`, `fill` et `press` de l'agent sont refusés (409 `human-needed`), avant d'atteindre la page. Test `test_the_agent_never_clicks_types_or_presses_on_a_challenge`. |
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
- CSP de `/captcha/` seulement : `default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`.
  Le reste de l'UI garde sa CSP.
- « J'ai fini » : `POST /api/captcha/done` (cookie + `X-BH: 1`, comme les autres POST). L'UI écrit
  `var/browser/captcha-done.json` (`{"t": ...}`), que l'hôte lit. Elle appelle aussi `human_done` dans le contrôleur.
  L'agent voit alors `human_done_at` dans `state()`.

### API de l'agent (`http://browser:8790/op`, en-tête `Authorization: Bearer $BH_BROWSER_TOKEN`)

| op | champs | réponse |
|---|---|---|
| `goto` | `url` (http/https seulement) | état |
| `fill` | `css`, `text` (≤ 2000) | `{"ok": true}` |
| `click` | `css` | état |
| `press` | `key` ∈ Enter, Tab, Shift+Tab, Escape, Backspace, Delete, Space, flèches, Home, End, PageUp, PageDown | état |
| `text` | — | `{"text": ≤ 8000 caractères, "truncated"}` |
| `wait` | `css` **ou** `ms` (≤ 30000) | état |
| `state` | — | `{"url", "title", "challenge": {"pending", "reason", "since"}, "human_done_at", "identity"}` |

- Tout le reste est refusé (400) : `cookies`, `storage`, `evaluate`, `screenshot`, `cdp`, les ops de l'hôte, ainsi
  que tout champ inconnu. Les URL `file:`, `chrome:`, `javascript:` et `view-source:` sont refusées aussi. Les
  touches de fonction (F12 ouvre DevTools) et les accords Ctrl/Alt sont exclus.
- Les sélecteurs passent par le moteur `css=` de Playwright, pas d'autre moteur.
- Chaque réponse est caviardée : valeurs de la session chargée (cookies, en-têtes), puis JWT, puis paramètres
  sensibles des URL (`bh.redact.url`). Test `test_no_reply_carries_a_session_value`.
- Le jeton vient de `secrets/browser.env`, créé en 0600 par `bh up` ou `bh browser up`. Compose le donne à l'agent
  et à bh-browser seulement, pas au juge ni au login.
- Le contrat est en place côté conteneur. Le brancher dans les outils de l'agent (`bh-browse`, prompt) relève d'un
  autre lot (N1 ou l'orchestrateur), et ce lot n'y a pas touché.

Détection « challenge en attente » (`detect.challenge`) : deux cas déclenchent la détection.
- Une frame visible servie par `challenges.cloudflare.com` ou l'un de ses sous-domaines. On lit `page.frames`, qui
  voit aussi les iframes en shadow root fermée.
- Un texte visible contenant « Security check », « Verify you are human », ou leur équivalent français.

Une frame Turnstile cachée (mode invisible, ou déjà passée) ne compte pas.

### Interface de l'hôte (`podman exec -i bh-browser python3 -I -c BOOT host`, JSON sur stdin)

`load_session` (cookies + liste de caviardage), `status`, `reset` (efface le profil, relance Chromium),
`human_done`. La réponse ne contient jamais de valeur. `load_session` rend le nombre de cookies chargés.

`bh browser load <scope.yaml> <identité>` lit `var/state/identities/<prog>/<nom>.json` avec `bh.gate.session.load`.
Il en tire les cookies de la jarre : un cookie host-only est posé par URL, un cookie de domaine par `.domaine`. Les
en-têtes, comme `Authorization`, ne sont **pas** injectés : un navigateur envoie les siens. Ils sont nommés à
l'écran.

## 3. Flux complet

1. L'agent pilote bh-browser (`goto`, `fill`, `click`…) et lit `state()`.
2. `state().challenge.pending == true`. Toute action sur la page est refusée (409).
3. Mio est prévenu. **Aujourd'hui, à la main** : `bh browser status` affiche `PENDING` et le lien. Le point d'appel
   `bh.browser_service.notify.captcha(program, identity, url)` existe mais reste vide : il n'y a pas de ntfy dans
   ce lot.
4. Mio ouvre `http://<ip-tailscale>:7340/captcha/`, se connecte à l'UI si besoin, voit l'écran et résout le
   challenge à la main.
5. Mio clique « J'ai fini ». `var/browser/captcha-done.json` est écrit, et `human_done_at` passe dans `state()`.
6. L'agent rappelle `state()`. Quand `pending` passe à `false`, il reprend. Si le challenge revient, la doctrine
   s'applique : `bh-note blocked captcha`, puis il passe à autre chose.

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
