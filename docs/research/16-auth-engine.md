# 16 — Moteur d'authentification (2026-11-25)

Agent J1 du swarm. But : obtenir et garder des sessions sans humain. Code : `src/bh/accounts/*`,
`src/bh/runner/run.py` (keeper, rôles), `src/bh/stack.py`, `container/compose.yaml`. Rien dans `src/bh/gate/*` :
les changements requis dans l'addon sont décrits au §7.

## 1. Résumé

- Trois kinds de recette : `json` (l'existant), `browser` (Chromium headless dans `bh-login`), `oauth_refresh`.
- `bh-login` : image de l'agent, réseau `sandbox` seul, derrière le gate. Piloté par l'hôte, rien gardé entre deux logins.
- MFA : TOTP RFC 6238 calculé sur l'hôte (vecteurs de l'annexe B validés). Code mail via `accounts/mail.py`.
- `expires_at` est renseigné : `exp` des JWT, `expires_in` OAuth, sinon cookies de session.
- Session keeper : un fil de l'hôte pendant le segment. Il renouvelle avant l'expiration et sur `session-dead`.
- Rôles : `BH_IDENTITY_ROLES="user-a=member@A,..."`, contrat avec J2.
- Preuve live : `user-c` de Juice Shop, login par le formulaire Angular, `whoami` rend son email (§8).

## 2. Recettes (`scope/model.py`, `accounts/recipe.py`)

Le champ `enroll.kind` vaut `json` par défaut. Schéma complet en tête de `accounts/recipe.py`.

| kind | Ce qui tourne | Session produite |
|---|---|---|
| `json` | un POST dans le gate (script stdlib sur stdin, proxy `127.0.0.1:8080`) | en-têtes du gabarit `{token}` + Set-Cookie du login |
| `browser` | `signup` HTTP facultatif dans le gate, puis des étapes dans `bh-login` | cookies du contexte en scope, `Authorization` vu sur la première requête authentifiée, clés `localStorage` rendues en en-têtes |
| `oauth_refresh` | POST `grant_type=refresh_token` vers `token_url`, dans le gate | `Authorization: Bearer {access_token}` (gabarit réglable) |

Étapes `browser` : `goto`, `fill`, `click`, `wait_for` (sélecteur ou fragment d'URL), `totp`, `email_code`, `select`.
Options : `optional` (click, wait_for), `timeout`. La première étape est un `goto`.

Contrôles au chargement du scope :
- chaque `goto`, `signup.url` et `token_url` est une URL http(s) en scope, sans gabarit ;
- un `fill`/`select` vers un champ dont le sélecteur nomme un secret (`password`, `otp`, `token`…) exige un gabarit ;
- les gabarits `localStorage` contiennent `{value}` et rien d'autre ;
- `browser` sans `origins` : l'hôte dérive `origins` des `goto` (M7, le bearer ne part pas vers tout le scope) ;
- `oauth_refresh` exige `origins` (ou une sonde) : sinon le jeton partirait vers tout hôte du scope.

Valeurs capturées refusées si elles ne tiennent pas dans un en-tête : `[\x21-\x7e]` pour un jeton, cookie-octet
RFC 6265 pour un cookie (pas de `;`), domaine de cookie hors scope ou suffixe public écarté.

## 3. Exécution du login navigateur (`accounts/browser.py`, service `login`)

1. L'hôte tue les process de `hunter` dans `bh-login` et efface `/tmp/bh-login-*` (`stack.reset_login`).
2. `podman exec -i --user hunter bh-login python3 -I -c BOOT`. `BOOT` lit `<longueur>\n<script>` sur stdin.
   Le payload suit sur stdin (étapes avec les valeurs rendues). Rien en argv ni dans l'environnement.
3. Le script crée un HOME neuf (et `TMPDIR`, donc le profil Chromium) et y installe la CA du gate dans deux bases
   NSS (`~/.local/share/pki/nssdb`, `~/.pki/nssdb`). Proxy `gate:8080`. Service workers bloqués. Images, polices et
   médias abandonnés localement.
4. Questions sur le même tube : `{"need":"totp"}` reçoit le code courant ; `{"need":"email_code"}` reçoit le
   code lu par l'hôte. La graine TOTP ne quitte jamais l'hôte.
5. Réponse : `{"result": {cookies, authorization, authorization_url, local_storage}}`. HOME supprimé ; second
   `reset_login` côté hôte, quoi qu'il arrive.
6. L'hôte construit la session et l'écrit avec `session.save` sous `session.lock` (atomique, 0600).

Le service `login` : pas de `/work`, pas de variable `ANTHROPIC_*`, volume `gate-ca` en lecture seule seulement.
Mesuré le 2026-11-25 : le relais répond `403 relay: only the agent and judge containers may use it` ; sans proxy,
aucune route (`curl --noproxy '*' https://example.com` → code 000).

## 4. MFA

- `accounts/totp.py` : HOTP RFC 4226 + TOTP RFC 6238. SHA-1/256/512, 30 s, 6 chiffres par défaut. Graine en
  base32, URI `otpauth://totp/` ou mapping. `fresh_code` attend la fenêtre suivante s'il reste moins de 5 s.
  `tests/test_totp.py` rejoue les 18 vecteurs de l'annexe B.
- Graine dans `secrets/identities/<prog>/<nom>.json`, champ `totp`.
- `email_code` : `mail.default().wait(alias, from, since, timeout ≤ 120 s)`. Seul un code de 4 à 10 chiffres est
  accepté. Pas de boîte ou jeton Gmail expiré : `MailError` ou `None`, donc échec propre (blocker `login-failed`
  par le runner). Testé avec `NoMailbox`.

## 5. Cycle de vie

`accounts/expiry.py`. Ordre de confiance :
1. `exp` d'un JWT (décodé **sans** vérifier la signature, seulement pour planifier) et `expires_in` OAuth ;
2. sinon, Max-Age/Expires des cookies dont le nom évoque une session (`sid`, `session`, `auth`, `token`…).
   Un `__cf_bm` de 30 min ne doit pas déclencher un login toutes les 25 min.
Le plus tôt gagne. Rien de connu : `expires_at` vaut `null`, le keeper ne renouvelle que sur `session-dead`.

Session keeper (`runner/run.py`, `SessionKeeper`) :
- démarré après `prepare_workdir`, arrêté avant `finish` (et sur exception) ; tick de 15 s ;
- identités gardées : celles offertes à l'agent, avec recette `enroll` et fichier de session ;
- `expiry` : `now ≥ expires_at − BH_KEEP_MARGIN_S` (120 s par défaut) → `refresh(force, probe_first=False)` ;
- `dead` : événement `session-dead` du journal du gate, de ce programme, lu depuis l'offset du début de segment,
  lignes complètes seulement. Une mort antérieure au dernier login du keeper est ignorée.
  → `refresh(force, probe_first=True)` : une sonde saine suffit, pas de login ;
- borne : 1 login par identité toutes les 300 s (meta `accounts-keeper:<nom>:<prog>`), succès ou échec ;
- échec : blocker `login-failed`, jamais d'interruption de l'agent. Le gate relit le fichier à chaque requête.

`refresh_identities` (avant segment et avant vérification) garde sa limite d'une tentative par heure.

## 6. Matrice de rôles (contrat J2)

- Identité : `role` et `tenant` facultatifs, `[A-Za-z0-9_.-]{1,32}`. Jamais des secrets.
- `agent_command` ajoute `BH_IDENTITY_ROLES`, même ordre que `BH_IDENTITIES`, identités vivantes seulement :

```
BH_IDENTITIES=user-a,user-b,admin-a
BH_IDENTITY_ROLES=user-a=member@A,user-b=member@B,admin-a=admin@A
```

- Champ absent : chaîne vide. `manual=@`, `admin-x=admin@`. Liste vide : variable vide.
- Lab bench : `user-a=member@A`, `user-b=member@B` (un compte inscrit est `member` sans équipe).

## 7. Changements requis dans l'addon du gate (non faits : `src/bh/gate/*` hors de mon périmètre)

Mesuré le 2026-11-25 (§8) : les requêtes de `bh-login` sont classées `target`, pas `enroll`. Le POST
`/rest/user/login` du navigateur a donc son échange complet écrit dans `var/state/flows/<id>.json`, mot de passe
et JWT compris (flow `1795617927-28490b-76`, compte de lab jetable). Elles comptent aussi comme trafic de l'agent.

Changement proposé dans `addon.py` :
1. `_from_gate(flow)` devient `_enrollment(flow)` : vrai pour `127.0.0.1`/`::1` **ou** pour l'IP du conteneur de
   login, résolue par nom (`BH_LOGIN_HOST`, défaut `login`) avec le même cache que `BH_AGENT_HOST`/`BH_JUDGE_HOST`
   du relais (60 s, relecture DNS bornée). `_record` met alors `class: enroll`, n'écrit pas `flows/<id>.json`, et
   l'ingestion l'ignore comme aujourd'hui.
2. Refuser `X-BH-Identity` venant de `bh-login` (403, fait `blocked`). Le login n'a jamais besoin d'une session.
   Sinon une page hostile chargée dans ce navigateur peut faire injecter la session d'une autre identité.
3. Relais : rien à faire, `bh-login` est déjà refusé (mesuré).
4. Après le changement : `podman restart bh-gate` n'est utile que si `policy.py` change ; `addon.py` est rechargé.

À purger par Mio : `var/state/flows/1795617927-28490b-76.json` (propriétaire `mio`, 0600 : un simple `rm`).

## 8. Preuve live (2026-11-25, 15:45)

Contexte : la stack tournait déjà, lancée depuis le checkout principal, avec `lab-bench` actif et du trafic de
test récent. Le gate y charge `src/` du checkout principal, qui ne connaît pas `kind: browser`. Pour ne pas casser
ce gate, la portée active a été remplacée ~7 s par une copie de `scopes/lab/juiceshop.yaml` où `user-c` n'a que
`probe` et `origins`, puis restaurée à l'identique (sha256 `93f92d21…` avant et après).

```
ln -s /home/mio/bb/bull-harness/var var                       # worktree : volumes relatifs du compose
podman-compose -f container/compose.yaml up -d --no-deps login
podman start bh-lab-juiceshop
BH_HOME=/home/mio/bb/bull-harness uv run bh accounts enroll scopes/lab/juiceshop.yaml user-c
  → user-c: signed up, logged in, probe ok                     (5 s)
podman exec --user hunter -e BH_DIR=/tmp/bhq bh-agent /opt/bh/bin/q -a user-c \
  http://10.231.0.10:3000/rest/user/whoami
  → [200] {"user":{"id":26,"email":"bh-user-c-1bcdc2@lab.local",...}}
```

Session écrite (noms seulement) : en-tête `Authorization: Bearer eyJ…` (depuis `localStorage.token`), cookies
`10.231.0.10` = `cookieconsent_status`, `language`, `token`, `welcomebanner_status`, `expires_at` ≈ +8 h (exp du
JWT). Fichiers de session et de secret en 0600. Après le login : aucun `/tmp/bh-login-*`, seul `sleep infinity`
tourne sous `hunter`. Ensuite `bh-login` supprimé, Juice Shop arrêté, lien `var` retiré : état d'avant restauré.

## 9. Ailleurs (hors de mon périmètre)

- `docs/architecture.md` §8 : mentionner le keeper (renouvellement pendant le segment) et `bh-login`.
- `cli.py` `bh status` : lister `bh-login`. `bh up` le crée déjà (compose).
- J2 : lire `BH_IDENTITY_ROLES` dans `bh.agent` et le prompt.

## 10. Incertitudes

- `oauth_refresh` non testé en live (pas de tenant Entra). `token_url` doit être en scope : pour MSRC,
  `login.microsoftonline.com` en `in_scope` l'ouvre aussi à l'agent. Le gate ne distingue pas encore un flux
  d'enrôlement d'un flux de chasse au niveau de la politique (seulement du journal). Décision de scope à prendre.
- Capture de `Authorization` par `request.headers` de Playwright : non mesurée seule (au lab, la valeur de
  `localStorage` la remplace). La doc Playwright exclut les en-têtes liés aux cookies, pas `Authorization`.
- `localStorage` : seule une valeur brute est lue. Un JSON (`{"token": …}`) n'est pas géré.
- Expiration par cookies : heuristique sur le nom. Un site au nom de cookie neutre n'a pas d'`expires_at`.
- Gmail : jeton expiré. `mail.default()` rend `GmailMailbox` (le fichier a un `refresh_token`), le refresh échoue,
  `MailError` → échec propre. Non rejoué en live.
- Empreinte TLS : la cible voit mitmproxy, pas Chromium (doc 10 §4). Un anti-bot peut refuser le login navigateur.
