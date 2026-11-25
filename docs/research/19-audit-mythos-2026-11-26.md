# Audit bull-harness, passage 1 (Mythos, 2026-11-26)

Lecture seule, rien exécuté. **P** = prouvé par le code cité. **S** = supposé (comportement de mitmproxy, Playwright, Chromium ou Copilot), avec la mesure qui tranche.

## 1. Verdict

- **Oui pour Sonnet après B1 à B8, comme chasse de cartographie et de contrôle d'accès HTTP.** Dans cet état elle ne peut pas sortir un finding de chat payable.
- Le harnais ne peut ni jouer la victime B dans le navigateur, ni enregistrer un finding de chat (`bh-note finding` exige une preuve HTTP), ni le faire vérifier (le juge n'a pas `bh-web`).
- La règle anti-bot ne tient que par la doctrine côté conteneur agent, qui embarque Playwright, Chromium et Xvfb. Le gate peut la tenir en dur (B2).
- **Non** si : B2 n'est pas fait, le profil de bh-browser peut mélanger deux comptes (B3), les jetons ne sont pas régénérés (B1), ou les mesures de B8 échouent.
- Opus et Mythos ne valent le coût qu'après I1 à I4 (preuve de chat, deux identités, lecture fiable, upload).

### Affirmations du contexte, vérifiées

| Affirmation | Constat |
|---|---|
| Contournement loopback corrigé | **P** `controller.py:378` (`<-loopback>`), refus `:105-117`. Les formes `127.1` ou décimales passent le regex mais partent au gate, qui refuse à la résolution (`policy.py:426`). |
| `_tunnel_name` | **P** `addon.py:402-403, 441-443, 518-520`. Testé avec un faux flux seulement (`tests/test_gate_sso_passthrough.py:435-451`). |
| Cas CDN `213.55…` | **P** couvert par le même repli : tout hôte IP dans un tunnel nommé, même port, reprend le nom. Cause « coalescence » : **S**, peu probable derrière un proxy HTTP. Trancher : zéro `blocked` avec URL en IP dans `events.jsonl` après une session. |
| Trames ws serveur journalisées | **P** `addon.py:941-950`, 200 caractères caviardés (`policy.py:656-661`). Le jeton du `ChallengeProof` est caviardé (`redact.py:32-35`). |
| ntfy une fois par challenge | **P** `watch.py:88-90`. Ni rappel ni plafond. |
| Verrou 409 pendant un challenge | **P** `controller.py:277-299`. `goto` n'est pas gardé (`:282-284`). |
| Fragilité 1 (juge) | **P**, et pire : `note.py:48, 87-93` refuse tout finding sans preuve HTTP à jumeau. |
| Fragilité 2 (trafic invisible) | **P** en partie : les routes vues par le gate arrivent dans la frontière à la rotation (`assets.py:226-236`), jamais les corps ni les trames. |
| Fragilités 3 et 4 | **P** `watch.py:43`, `browser_service/__init__.py:34`, `policy.py:304-305`. |
| Fragilité 5 (`eventid`) | **P** `policy.py:85, 391, 399`. |
| Fragilité 7 (cartes) | **P** `run.py:653-671`. Aucune carte au premier leg (`:1273, 1378`). |

## 2. Bloquants (avant Sonnet)

**B1 | critique | `notify.py:24-41`, `ui/server.py:71-77, 541, 535`**
- Problème : le jeton de l'UI et le topic ntfy ont fuité et rien ne les fait tourner.
- Preuve (P) : le jeton UI ouvre `/api/run` (lancer une chasse avec `--task`), `/api/identities` (poser une session) et l'écran `/captcha/`. Un topic ntfy.sh est ouvert en écriture à qui connaît son nom : faux push « captcha à faire » avec un `Click` arbitraire.
- Correctif : supprimer `secrets/ui.token` et `secrets/ntfy.env`, relancer l'UI, réabonner le téléphone. Ajouter `bh notify rotate`.
- Test : l'ancien cookie UI rend 401 ; un POST sur l'ancien topic n'arrive plus.

**B2 | critique | `policy.py:246-251, 280-288, 519-523` ; `browse.py:616-625` ; `prompt.py:71-73, 187-212`**
- Problème : rien n'empêche le conteneur agent de charger Turnstile dans son propre navigateur et d'y cliquer, ni d'ouvrir lui-même le websocket du chat sans passer par le challenge.
- Preuve (P) : `_support_client` ne restreint que `auth`. Passthrough et websockets sont ouverts à tout client du sandbox. L'image agent contient Playwright, Chromium, Xvfb (`Containerfile:69-70, 82, 97-98`). `bh-browse --click` n'a aucune garde de challenge. La règle anti-bot n'est pas dans `VERIFIER_DOCTRINE`.
- Preuve (S) : repli SSE ou long-polling du hub de chat. Chercher `/negotiate` dans `flows.jsonl`.
- Correctif :
  - `_browser_ips()` sur le modèle de `_login_ips` (`addon.py:193-198`).
  - Quand le scope a un hôte passthrough, refuser hors bh-browser le CONNECT passthrough et le handshake websocket.
  - Clé de scope `browser_only: ["/m365Copilot/Chathub/"]`, refusée hors bh-browser quelle que soit la méthode.
  - Paragraphe anti-bot ajouté au juge.
- Bénéfice annexe : ferme le domain fronting dans le tunnel (limite connue, `architecture.md:244-248`).
- Test : depuis bh-agent, `curl https://challenges.cloudflare.com/turnstile/v0/api.js` et un handshake ws Python vers substrate rendent 403 avec la raison « browser only ». Depuis bh-browser, le chat marche. L'enrôlement `bh-login` passe encore.

**B3 | critique | `watch.py:43-45`, `controller.py:316-323, 332-336`, `compose.yaml:196`**
- Problème : `prepare()` empile les cookies de la première identité vivante sur un profil persistant qui peut contenir l'autre compte.
- Preuve (P) : `load_session` fait `add_cookies` sans `reset`. `Controller.identity` vit en mémoire, le profil sur un volume. Scénario : trois 401 sur trois routes sous user-a (`session.py:53`), user-a marqué périmé à l'ingestion, segment suivant `identities[0] = user-b` chargé dans le profil de user-a.
- Preuve (S) : le cache MSAL en localStorage reste celui de user-a.
- Impact : faux finding « fuite entre comptes », la classe que MSRC paie le plus.
- Correctif : marqueur `{program, identity}` écrit dans `/profile`. `load_session` refuse une autre identité sans `reset` préalable. `prepare()` lit `status`, fait `reset` si l'identité ou le programme diffère, puis charge. `state()` lit le marqueur.
- Test : unitaire (charger a, préparer b : `wipe` avant `add_cookies`). Live : `bh browser status` après redémarrage du conteneur nomme la bonne identité.

**B4 | haute | `detect.py:16-22, 40` ; `controller.py:519-524, 527`**
- Problème : la détection du challenge est fragile dans les deux sens.
- Preuve (P) : le libellé mesuré « Verification required » n'est pas dans `CHALLENGE_TEXT`. Si `frame_element()` lève, `visible` reste `False` : échec ouvert, `click` et `press` passent. Le texte est cherché dans tout le corps, donc dans la conversation : un prompt ou une réponse contenant « security check » verrouille l'agent et réveille Mio.
- Correctif :
  - Ajouter `verification required|vérification requise`.
  - Exception sur une frame d'hôte challenge : `visible=True`.
  - La règle texte ne compte que s'il existe une frame d'hôte challenge, ou un titre d'interstitiel, ou une page de moins de 600 caractères.
  - Fixture : le snapshot réel de cette nuit.
- Test : `challenge()` rend `pending` sur la fixture Copilot, pas sur une conversation qui cite « security check », et `pending` quand `visible` est indéterminé.

**B5 | haute | `scopes/msrc/copilot.yaml:24-25`**
- Problème : `substrate.office.com` et `substrate.svc.cloud.microsoft` sont des cibles entières, alors que la note dit « our own conversations only ».
- Preuve (P) : règle `domain`, donc tous chemins et toutes méthodes, PUT, PATCH et DELETE compris sous identité. `bh-crawl`, `bh-authz` et `q` peuvent viser tout le substrat M365.
- Correctif : règles `url` (`https://substrate.office.com/m365Copilot/` plus les préfixes exacts vus cette nuit pour UsageStatus, userconfig, prompts, suggestions). `enforce.py:93-109` autorise le CONNECT et juge chaque chemin.
- Test : `bh scope check scopes/msrc/copilot.yaml https://substrate.office.com/api/v2.0/me/messages` refusé, le chemin Chathub admis, et le chat marche en live.

**B6 | haute | `copilot.yaml:49-113` ; `run.py:278-279` ; `enroll.py:624` ; `prompt.py:129-131`**
- Problème : aucune identité n'a de `probe`, donc rien n'est vérifié, et le prompt affirme le contraire.
- Preuve (P) : fichier présent et pas de marque, donc identité offerte sans requête. Le keeper rend « session kept (no probe declared) ». Le bearer capturé ne part que vers `origins` (copilot.com, copilot.microsoft.com), donc `q -a` vers substrate part sans `Authorization` (`addon.py:695-698`).
- Preuve (S) : statut réel de `q -a user-a` et `q -a user-b` sur une API Copilot, à T0 et à T0+90 min.
- Impact : sans deux identités HTTP qui marchent, aucune preuve entre comptes n'est possible. Un 401 général sera lu comme « refus d'accès, le contrôle du finding ».
- Correctif : mesurer, puis déclarer `probe: {url, status: 200, expect: <texte propre au compte>}` par identité. Sans sonde, `scope_block` dit « sessions non vérifiées ».
- Test : `qq <URL d'API authentifiée>` rend user-a 200, user-b 200 sur ses propres données, anonyme 401. `bh accounts ls` montre `probe ok`.

**B7 | haute | `cards/prompt-injection.md:6-8` ; `prompt.py:70` contre `:121-123` ; `db.py:385` avec `contract.py:82` ; `prompt.py:81-88`**
- Problème : quatre consignes contradictoires ou dangereuses sur Copilot.
- Preuve (P) :
  1. La carte dit « Use an HTTP path to the same assistant when one exists » : c'est chercher un chemin sans challenge. Elle dit aussi « websockets refused : blocked », faux depuis `websockets: true`.
  2. « never wait for help » contre « `bh-web wait-human` ».
  3. `bh-note blocked captcha` s'affiche sept jours sous « blocked (do not retry) » : une notification manquée ferme le chat pour Opus et Mythos.
  4. Aucune voie pour un finding visible seulement dans le navigateur : le modèle fabriquera une preuve HTTP ou perdra le finding.
- Correctif : réécritures R1, R2, R5, R7 de la section 6. TTL de 30 min pour `captcha` et `challenge` quand le scope a un hôte passthrough, sous le titre « retry: `bh-web state` ».
- Test : `tests/test_prompt.py` vérifie l'absence de « HTTP path » dans la carte et la présence de l'exception `wait-human`. Un blocker captcha de 31 min n'est plus dans la frontière.

**B8 | haute | mesures live, portes d'entrée**
- Problème : cinq comportements non mesurés peuvent rendre la chasse inopérante.
- Mesures et critères :
  1. **Durée de vie du websocket.** Le gate tue à 600 s (`policy.py:543`) et `flow.kill()` ne ferme pas la connexion (`architecture.md:255-257`) : elle devient un trou noir. Page ouverte 11 min, puis un message. Critère : réponse sans nouveau challenge, sinon `BH_WS_MAX_SECONDS=3600`.
  2. **Trames client par minute au repos**, borne 12 (`policy.py:541`). Compter les `ws-message` `from: client` par minute dans `events.jsonl`. Critère : moins de 6.
  3. **Méthodes de l'appli refusées.** Compter les `blocked` dont la raison contient « only as one of your identities » (`policy.py:304-305`). Critère : liste connue et jugée non vitale, sinon I2 d'abord.
  4. **404 de l'appli**, garde à 25 en 5 min (`policy.py:82, 371-384`). Critère : moins de 10 sur 5 min de navigation.
  5. **Paramètres de lancement.** `--minutes` vaut 30 par défaut (`cli.py:781`). Lancer avec `--max-turns 100 --minutes 240`.

## 3. Importants (avant Opus et Mythos)

**I1 | haute | `note.py:48` ; `proof.py:139-154` ; `verify.py:311-313, 362-370` ; `compose.yaml:123`**
- Problème : aucun chemin de preuve ni de jugement pour un finding de chat. Une preuve fabriquée coûte deux sessions de juge pour finir `inconclusive`.
- Preuve (P) : le jumeau HTTP même méthode, même origine, même chemin ne décrit pas un flux causal d'IA. Le juge n'a pas `BH_BROWSER_TOKEN`.
- Correctif : type de preuve `observation`, vérifié par l'hôte sur le journal du gate, que le chasseur ne peut pas écrire.
  - Oracle : un secret aléatoire `BH-SECRET-<16 hex>` planté dans les seules données de B, vu ensuite côté A (trame serveur ou flux étiqueté A) ou dans une URL demandée par le navigateur de B vers un hôte nommé par la seule charge de A.
  - Le gate cherche ce motif dans la trame entière et ne journalise que le hit.
  - Statut `verified-evidence`. Le juge lit la table de l'hôte et ne peut que l'abaisser.
  - Mio rejoue une fois avant de soumettre.
- Test : lab d'injection. Un secret vu des deux côtés donne `verified-evidence`, un secret tapé par A donne `rejected`.

**I2 | haute | `browser_service/__init__.py:34` ; `policy.py:304-305` ; `addon.py:610-620, 722-724`**
- Problème : une seule identité dans le navigateur, et son trafic n'a pas d'identité au gate.
- Preuve (P) : pas d'op de changement. Sans `X-BH-Identity`, PUT, PATCH et DELETE de l'appli sont refusés, les `Set-Cookie` ne rejoignent pas la jarre, et les événements portent `identity: null`.
- Correctif en deux temps :
  - Minimal : `bh-web switch <identité>` consigne la demande, le watcher de l'hôte fait `reset` puis `load_session`. Coût : un challenge par bascule. L'hôte écrit l'identité chargée dans `active-run`. Le gate étiquette le trafic de l'IP de bh-browser et lui ouvre les méthodes réservées, sans rien injecter.
  - Propre (**S**, à valider sur Playwright 1.65.2 attaché en CDP) : un second contexte pour user-b dans le même Chromium, `bh-web -a user-b …`, étiquette par `Proxy-Authorization` lue au CONNECT.
- Test : un DELETE de l'appli passe et porte `identity: user-a`. Depuis l'agent, il reste refusé.

**I3 | haute | `controller.py:52, 308-310, 490-492` ; `hooks.py:22-24, 100-115`**
- Problème : le chasseur lit mal les réponses et pilote à l'aveugle.
- Preuve (P) :
  - `text` rend les 8000 premiers caractères du corps. Dans un chat, la dernière réponse est à la fin.
  - Le hook remplace toute sortie de plus de 80 lignes par 30 lignes de tête et 12 de queue : le milieu, donc la réponse, disparaît.
  - Aucune op pour lire un attribut (`href`, `value` d'un lien de partage), lister les contrôles ou changer d'onglet. `_page()` prend `pages[-1]` : une popup capture le pilotage.
  - Cliquer « joindre » ouvre un sélecteur de fichier natif que personne ne ferme (**S**).
- Correctif : `text {css?, tail?}`, `outline` (`aria_snapshot` borné), `attr {css, name}`, `net` (méthode, URL caviardée, statut, refus du gate), `tabs`, `upload {css, name, content_b64 ≤ 256 Kio}` via `set_input_files` en mémoire. Exempter `bh-web text` du hook.
- Test : après 20 échanges, `bh-web text --tail 3000` montre la dernière réponse en entier.

**I4 | moyenne | `addon.py:933-950`**
- Problème : pas de trames websocket pour le chasseur (identifiants de conversation, appels d'outils, citations).
- Correctif : tampon borné dans le contrôleur (`page.on("websocket")`), caviardé. Les trames `ChallengeProof` et toute clé `token` sont exclues en dur. `bh-web frames --last N`.
- Test : aucune sortie ne contient la valeur d'un jeton de challenge.

**I5 | haute | `contract.py:572, 578-605` ; `hooks.py:49-67`**
- Problème : une URL dans le texte d'un `bh-web fill` ou dans un sélecteur déclenche le verrou d'outils.
- Preuve (P) : `urls_in` prend toute URL littérale de la commande. Le refus demande `bh-crawl` sur l'hôte cité, même hors scope, et l'URL est notée « testée ».
- Correctif : pour `bh-web`, seul l'argument de `goto` est une destination.
- Test : `bh-web fill textarea "résume https://example.org/x"` n'est ni verrouillé ni noté.

**I6 | moyenne | `policy.py:308, 386-421, 371-384` ; `addon.py:799-804`**
- Problème : les gardes du gate s'appliquent au trafic propre de l'appli.
- Preuve (P) : plus de 4 identifiants en 10 min par route. Cela refuse la télémétrie `events?eventid=` et refusera la 5e conversation ouverte.
- Preuve (S) : la 5e Chathub si le handshake porte un cookie. 404 et pause WAF d'une heure si le trafic du navigateur reçoit des pages de challenge.
- Correctif : pour l'IP de bh-browser, pas de pause WAF ni de garde 404. La garde d'énumération ne compte que les identifiants de chemin (pas `eventid`), avec une borne de 12.
- Test : unitaire par client. Live : huit « New chat » en 10 min sans refus.

**I7 | haute | `run.py:1273, 1378` ; `classes.py:28, 324-343`**
- Problème : la seule connaissance métier n'arrive pas de façon fiable.
- Preuve (P) : aucune carte au premier leg. Ensuite 3 cartes au plus, choisies par signaux d'endpoints et pénalisées si récentes.
- Correctif : clé de scope `cards: [...]`, toujours injectées. Montage en lecture seule de `src/bh/cards` sous `/opt/bh/cards` pour l'outil Read.
- Test : le prompt du premier leg contient la fiche Copilot.

**I8 | moyenne | `prompt.py:35-60, 158-160`**
- Problème : la doctrine décrit des outils interdits sur ce programme.
- Preuve (P) : « Map it with the arsenal first (recon, crawl, content, scan) » et « TOOL LOCK … `bh-crawl`, `bh-content` and `bh-scan` » alors que `scope_block` dit FORBIDS et que seul `crawl` est requis (`contract.py:134-136`).
- Correctif : générer Arsenal, Method et TOOL LOCK selon `scope.scanners_on`.
- Test : aucun nom d'outil interdit dans le prompt d'un scope sans scanners.

**I9 | moyenne | `run.py:59, 71-72, 1333, 1367`**
- Problème : seuils de contexte calibrés sur Juice Shop.
- Preuve (P) : rotation à 30 k, arrêt dur à 60 k, 3 legs au plus. Une chasse navigateur y arrive en 20 à 45 tours, donc environ 135 tours au maximum (**S** sur le rythme), et chaque session neuve oublie sélecteurs et état de page.
- Correctif : `BH_CONTEXT_ROTATE_TOKENS=60000` et `MAX_LEGS=5` pour ces chasses. `auto_handoff` ajoute l'état de `bh-web` (URL, identité, challenge).
- Test : un segment de 150 tours utilise son budget.

**I10 | haute pour l'étape 3 | `policy.py:762-765` ; `compose.yaml:59-61` ; `verify.py:48-51`**
- Problème : `claude-mythos-5-2` n'est pas dans la liste du relais pour l'agent, donc la chasse Mythos sera refusée. À l'étape Opus, le juge est le modèle du chasseur.
- Correctif : `BH_RELAY_MODELS_AGENT` dans l'environnement du gate. `BH_VERIFIER_MODEL=claude-mythos-5-2` pour la chasse Opus.
- Test : un `count_tokens` puis un message Mythos passent depuis l'agent.

**I11 | haute, règle MSRC | `contract.py:67-81` ; `notify.py:60-63` ; `run.py:1062`**
- Problème : « donnée d'un tiers vue » et « exécution côté serveur » n'ont ni raison dédiée ni alerte, et l'ingestion n'a lieu qu'en fin de segment. MSRC demande un signalement immédiat (doc 15).
- Correctif : raisons `third-party-data` et `server-exec`. Le watcher suit `notes.jsonl`, pousse un ntfy sans contenu, arrête le segment et parque le programme.
- Test : la note déclenche push et arrêt en moins de 30 s.

**I12 | moyenne | `watch.py:81-92` ; `notify.py:44-57` ; `web.py:30` contre `run.py:53` ; `controller.py:282-284`**
- Problème : la boucle humaine est fragile.
- Preuve (P) : un push par challenge, sans rappel ni plafond (un texte qui clignote donne un push toutes les 10 s). Les erreurs sont avalées. `wait-human` dure 480 s alors que le Bash par défaut coupe à 330 s. L'agent peut faire `goto` pendant que Mio clique.
- Correctif : au plus un push par 5 min, rappel à 10 min, erreur dite une fois. `WAIT_HUMAN_S=300`. Tant qu'un tunnel `/captcha/ws` est ouvert, seules `state` et `text` sont permises.
- Test : `tests/test_browser_watch.py` étendu.

**I13 | moyenne | `policy.py:340-349` ; `addon.py:663-667`**
- Problème : sur un hôte `sso`, tout GET est permis à l'agent avec les cookies de l'identité. Il peut sonder `authorize` avec n'importe quel `client_id` et échanger des codes, alors que ces hôtes ne sont « jamais des cibles ».
- Correctif : `get_paths` par hôte `sso`, sur le modèle de `token_paths`. Une phrase de doctrine.
- Test : `q -a user-a https://login.microsoftonline.com/common/oauth2/v2.0/devicecode` refusé.

**I14 | moyenne | `browse.py:169-171, 736-737` ; `contract.py:503`**
- Problème : `bh-browse --xss` est classé scanner, donc refusé ici. Un XSS de rendu ne peut pas être confirmé par le chasseur.
- Correctif : un rendu d'une seule page avec marqueur est une observation, pas un scan. Décision de Mio.
- Test : `bh-browse <url> --xss m123` passe avec `BH_SCANNERS=0`.

**I15 | moyenne | `tests/escape/escape_check.sh:1-65`**
- Problème : la suite d'évasion ne teste ni `sso`, ni `passthrough`, ni websocket, ni l'API de bh-browser. Les tests du gate utilisent des `SimpleNamespace`, alors que les correctifs dépendent d'internes de mitmproxy.
- Correctif : profil `msrc` de la suite : POST `sso` hors `token_paths`, SNI différent du CONNECT, API navigateur sans jeton, `goto` loopback, B2.
- Test : la suite passe sur le gate réel, en vérifiant la raison de chaque refus.

**I16 | moyenne | `run.py:866, 887` ; `cli.py:219-220, 321-334, 352-360`**
- Problème : le texte du chasseur arrive brut dans le contexte de l'orchestrateur, qui a le shell de l'hôte et les secrets.
- Correctif : `--quiet` pour les runs pilotés. `bh finding` et `bh board` encadrent les champs du chasseur d'une balise à nonce. Règle écrite dans le CLAUDE.md de l'orchestrateur.
- À faire aussi : mettre à jour les skills périmées (`msrc-ai-bug-bounty/SKILL.md:189-190`, `ai-red-team-pyrit/SKILL.md:122-132` disent encore « websocket refusé, trouver le chemin HTTP »).

**I17 | moyenne, conformité**
- Problème : « never a flood of prompts » n'est que de la prose. `FILL_MAX` borne la taille d'un prompt, rien ne borne leur nombre.
- Correctif : budget de `fill` par segment dans le contrôleur, erreur claire une fois épuisé.
- Test : le 81e `fill` est refusé.

**I18 | moyenne | `addon.py:491-498, 924-930` ; `policy.py:621-622`**
- Problème : un tunnel passthrough ou un websocket expiré devient un trou noir. Un challenge demandé plus de 10 min après le premier peut ne pas se charger (**S**).
- Correctif : mesurer (navigateur inactif 15 min, puis un challenge), puis relever les bornes ou fermer réellement la connexion.

**I19 | moyenne | `browse.py:583-585, 664` ; `proof.py:67-78`**
- Problème : le chasseur peut lire les jetons de nos comptes de test (**S** pour le contenu, `Authorization` dans `har.json`, cache MSAL dans `browse-state-*.json`). Il peut les rejouer avec `q -H`, mais une preuve ne peut pas porter `Authorization`.
- Correctif : en-têtes d'identité par origine dans la session et capture par audience. Caviarder les entrées `sso` du HAR.
- Test : `q -a user-b` sur une API substrate rend 200 sans jeton en clair dans `commands.jsonl`.

## 4. Mineurs

- Textes périmés : `browser_service/__init__.py:15` (« notify empty »), `addon.py:45-46`, `architecture.md` §Websockets, `docs/TODO.md:44`.
- Corps des flux non caviardés (`addon.py:877, 881`).
- `copilot.yaml:114` renvoie le chasseur vers `.claude/skills`, qu'il ne peut pas lire.
- Le prompt du juge liste toutes les identités et la ligne `bh-web`, qu'il ne peut pas utiliser (`prompt.py:245`).
- katana n'exclut pas les liens de déconnexion (`tools.py:507-539`) : ajouter une exclusion `logout|signout`.
- Chaque trame d'un websocket zombie écrit un `blocked` (`addon.py:893-900`).
- `Controller.secrets` ignore les cookies posés après le chargement (`controller.py:320`).
- `bh-recon` ne produit ici que des refus : la fiche doit dire de le sauter.
- L'écran `/captcha/` montre du contenu de la cible à Mio : n'y taper rien d'autre que le challenge. Ajouter `-noclipboard` à x11vnc.
- `copilot.ai` : ne l'ajouter qu'après avoir vu ce qu'il sert.

## 5. Ce qui manque (par impact sur la chasse)

1. **B comme victime dans le navigateur** (I2). Sans lui, pas d'injection indirecte ni de test de mémoire.
2. **Preuve et juge pour le chat** (I1). Sans eux, un vrai finding finit en `fact`.
3. **Lecture fiable et pilotage** : `text --tail`, `outline`, `attr`, `net`, `tabs` (I3).
4. **Upload** de document ou d'image : le vecteur indirect le plus accessible sans connecteur.
5. **Récepteur hors bande** (issue 31). Substitut immédiat : une requête du navigateur de B vers un hôte nommé par la charge de A, refusée et journalisée par le gate.
6. **Connecteurs** : le consentement passe par des hôtes `auth`, refusés dans bh-browser (`policy.py:521-522`). Il faut aussi un moyen d'envoyer un mail à B. Prérequis manuels de Mio.
7. **Captures d'écran côté hôte** pour le rapport MSRC (op hôte seulement).
8. **Drapeaux de fonctionnalités** : `ecs.office.com` et `config.edge.skype.com` sont refusés, donc l'appli tourne peut-être sans certaines surfaces (**S**).
9. **Jetons par origine** pour `q` et les preuves (I19).

## 6. Bonnes pratiques et mots-clés

Ce qui marche et qu'il faut garder :
- Les états finaux dits sans échappatoire (« out of scope is final », `prompt.py:18`).
- La structure When / Do / Watch / Never des cartes.
- `--not-proven`.
- « Default stance: disbelief » pour le juge.

Ce qui fait dériver :
- **Consignes contradictoires** (B7, I8). Un modèle tranche au hasard.
- **Quantités vagues** : « a few variants », « low rate », « nearly spent ». Donner des nombres.
- **Auto-certification** : « all must be yes » (`prompt.py:76`) sans pièce exigée par question.
- **Méthode centrée endpoint** pour un produit d'IA (`prompt.py:54-60`, `run.py:61-65`).
- **Règle dure enterrée** dans la section Board (`prompt.py:71-73`).
- **Fin de tâche qui amorce l'arrêt** : « end with a 5-line summary » en dernière phrase (`prompt.py:181`).

Réécritures :

**R1, anti-bot.** À déplacer sous « Network (hard rules) », avec la raison et la voie permise.
- Avant (`prompt.py:71-73`) : « Anti-bot challenges … are never solved, evaded or worked around … A challenge you cannot pass as a normal browser is `bh-note blocked captcha`; move on. »
- Après : « Anti-bot challenges (Turnstile, captcha, WAF pages): only the operator passes them, by hand, in `bh-web`. Why: breaking one gets the account and the program banned. You never click, type or press on one, never open the challenge in another browser, never send a chat message by any path other than `bh-web` (no direct websocket, no API call that carries a prompt), never test whether the server checks the token. When one appears: `bh-web wait-human` once; still pending, work an HTTP surface and run `bh-web state` every 10 turns. »

**R2, attente.**
- Avant (`:70`) : « Nobody unblocks you during the hunt: never wait for help, never end a segment because of a blocker. »
- Après : « Nobody unblocks you, with one exception: a human challenge in `bh-web` (see Network). For everything else, never wait and never end a segment on a blocker. »

**R3, identités.**
- Avant (`:129-131`) : « The harness checked their sessions before this segment: a 401/403 on one object is an access refusal … »
- Après, avec sonde : inchangé. Sans sonde : « Sessions were NOT checked. Before any access-control conclusion, run `qq <a page of your own account>`: each identity must get 200 with its own data. 401 everywhere is a dead session, not a finding's control. »

**R4, première tâche** sur un scope sans scanners avec navigateur.
- Avant (`:158-160`) : « First session on this program. Map it with the arsenal first (recon, crawl, content, scan). »
- Après : « First session. Spend at most 15 turns mapping: `bh-crawl` once per in-scope origin, one `bh-browse <app url> --as user-a` to list the API calls and controls, then `bh-web state`. Then work the surfaces of the program card, top first. »

**R5, finding visible seulement dans le navigateur** (provisoire, avant I1).
- Ajout après `:88` : « A result you can only show in `bh-web` is not recorded with `bh-note finding`. Record `bh-note fact "CANDIDATE: <title>" -s "<victim, what crossed, k/N, conversation ids from /id>" -e <file with the exact prompts and outputs>`. Never write a proof.json that does not replay the impact. What Copilot says it did is not evidence: only a secret you planted in B's data and then saw as A, or a state change you read back, counts. »

**R6, sept questions.**
- Après : « For each question, name the file or the output line that shows it; a question without one is a no. »

**R7, carte prompt-injection, étape 1.**
- Avant (`cards/prompt-injection.md:6-8`) : « Measure the transport first: `bh-browse` … "websockets: N refused" means the chat is unreachable … Use an HTTP path to the same assistant when one exists. »
- Après : « The chat is driven with `bh-web` only (program card). Never look for another path to send prompts. »

**R8, relance** (`run.py:61-65`). Ajouter : « …or the next unchecked surface of the program card. »

**R9, juge.** Ajouter à `VERIFIER_DOCTRINE` le paragraphe R1 et : « For an AI finding, the model's own statement is never evidence. »

**R10, sortie de `bh-web text`.** L'encadrer d'une balise à nonce, que la doctrine nomme comme donnée de la cible.

Pratiques de code violées :
- Contrôle de sûreté en échec ouvert (`controller.py:520`).
- Règle de sécurité tenue par le prompt alors que le gate peut la tenir (B2).
- État décrivant des données persistantes gardé en mémoire (B3).
- Constantes couplées non liées (480 s et 330 s, `TEXT_MAX` et `MAX_CHARS` à 8000).
- Exceptions avalées sans trace (`watch.py:91-92`, `notify.py:56-57`).
- Contraintes du scope écrites en prose (B5).
- Tests sur des faux objets pour du code qui dépend des internes de mitmproxy (I15).

## 7. Plan des skills/cartes Copilot

**Format recommandé, trois étages :**
- **Fiche programme épinglée** (clé `cards:` du scope, I7), toujours présente, 60 lignes au plus.
- **Cartes de classe** par le mécanisme actuel, avec leur standard de preuve dans `classes.py`, que le juge applique.
- **Playbooks lus à la demande** avec l'outil Read sous `/opt/bh/cards/`, listés par la fiche.

En attendant I7, la fiche passe par `bh run --task "…"` (`run.py:1275`). Les `.claude/skills/msrc-*` restent à l'orchestrateur.

**Surfaces par rendement attendu.** L'existence de chaque fonction est **S** (connaissance générale, non vérifiée ici) : à confirmer par `bh-browse` et `bh-web text`.

| # | Surface | Gain MSRC | Prouvable aujourd'hui |
|---|---|---|---|
| 1 | Contrôle d'accès HTTP entre nos deux comptes (historique, pièces jointes, images générées, entrées de mémoire) | Important (lecture des conversations d'autrui) | Oui, étage A, si B6 passe |
| 2 | Partage (liens, pages, groupes) : cycle de vie du lien, contenu rendu chez le lecteur | Important à critique | En partie (HTTP, I14) |
| 3 | Injection indirecte (page partagée par A, document de A envoyé par B, page lue par Copilot) | Critique en zéro clic, moindre avec interaction | Non (I1, I2, upload) |
| 4 | Mémoire et personnalisation : persistance d'une consigne injectée, fuite entre conversations | Important | Non (I2) |
| 5 | Rendu de la sortie du modèle (markdown, liens, images) | Moyen, très durci | Oui, par les refus du gate |
| 6 | Dépôt de fichier classique (type servi, URL d'accès) | Moyen | Non (upload) |
| 7 | Web classique sur copilot.com (redirection ouverte, CORS, CSRF) | Faible à moyen | Oui, étage A |
| 8 | Connecteurs et actions | Le plus haut | Non (prérequis de Mio) |
| 9 | Jailbreak, prompt système, contenu nuisible | Nul | Ne pas y passer un tour |

**Cartes à écrire :**

**C0 `msrc-copilot`, fiche épinglée.**
- Quand : toujours sur ce programme.
- Contenu : cibles et hôtes interdits ; l'identité que nomme `bh-web state` ; budget de prompts ; au plus 4 nouvelles conversations par 10 min ; ne jamais faire `goto` si `state` montre déjà le chat ; ne pas cliquer « joindre » ; sauter `bh-recon` ; le tableau des surfaces.
- Barème (source : skill `msrc-ai-bug-bounty`, à revérifier sur la page) : zéro clic avec exfiltration ou action privilégiée, critique ; avec interaction, un cran dessous ; soi-même, contenu seul ou prompt système, rien.
- Arrêts : donnée d'un tiers ou exécution serveur, `bh-note blocked` sans contenu.
- Champs de rapport : URL exacte, compte personnel, « MSOBB » dans le nom, réglages, prompts mot pour mot, identifiant par `/id`, k/N, heures UTC.

**C1 `bh-web-manual`, pilotage.**
- Quand : tout scope avec hôte passthrough.
- Techniques :
  - `bh-web state`.
  - Trouver les contrôles : `bh-browse https://copilot.com/chat --as user-a --timeout 300`, puis `grep -n -i 'button\|textbox' $BH_DIR/raw/browse-*/aria.yml`.
  - Sélecteurs CSS seulement : `button:has-text("New chat")`, `[aria-label="…"]`.
  - Envoyer : `bh-web fill '<composer>' '…'`, `bh-web press Enter`, `bh-web wait 5000`, `bh-web text`.
  - Noter aussitôt : `bh-note fact "copilot selectors" -s "…" -k recon`.
  - Identifiant : envoyer `/id`.
- Pièges : sortie tronquée (I3), popup, challenge.
- Preuve : aucune, c'est un mode d'emploi.

**C2 `ai-conversation-isolation`** (classe `idor`, alias `ai-input-extraction` à créer).
- Quand : une API porte des identifiants de conversation, de fichier ou de mémoire.
- Techniques : lister les appels avec `jq -r '.log.entries[]|"\(.request.method) \(.response.status) \(.request.url)"' $BH_DIR/raw/browse-*/har.json | sort -u`. Créer un objet par compte, puis `qq <url de l'objet de user-a>`, puis `q -a user-b -X …` sur ses propres objets seulement.
- Pièges : 401 partout = session morte ; 200 vide n'est pas un accès ; jamais d'énumération.
- Preuve juge : `proof.json` (attaque : B lit le marqueur de A ; contrôle : anonyme refusé).
- Preuve MSRC : identifiants des deux conversations, les deux comptes nommés.

**C3 `copilot-share`** (classe `broken-access-control`).
- Quand : partage, page, groupe.
- Techniques : partager comme user-a, lire le lien (`attr`, I3), `qq <lien>`, révoquer, relire, modifier la conversation après partage.
- Pièges : un lien public lisible par tous est voulu ; ne jamais deviner des liens.
- Preuve : jumeau avant et après révocation.

**C4 `prompt-injection`, réécrite** (classe existante, `classes.py:213-233`).
- Quand : un contenu de A est lu par l'IA de B.
- Techniques : planter `BH-SECRET-<16 hex>` dans les données de B. A écrit une consigne bénigne demandant de le porter dans un canal que A lit. B fait une demande ordinaire. 3 essais avec charge, 3 sans.
- Pièges : le secret tapé par A ; la phrase du modèle prise pour une preuve ; plus de 5 variantes par surface.
- Preuve juge : type `observation` (I1).
- Preuve MSRC : k/N, prompts, identifiants, interaction requise de B.

**C5 `ai-output-rendering`** (classe `xss`).
- Quand : la réponse rend du markdown, des liens ou des images.
- Techniques : faire produire un marqueur dans chaque contexte de rendu, lire le DOM par `bh-browse` sur la page partagée, `bh-web net --denied` (I3) pour une requête sortante.
- Pièges : l'exfiltration par image markdown est citée comme corrigée (skill, `SKILL.md:54-57`) : chercher une variante.
- Preuve : étape `browse` avec marqueur (I14) ou refus du gate portant l'URL.

**C6 `ai-memory`** (alias de `prompt-injection`).
- Quand : la mémoire est active.
- Techniques : comme B, lire l'état de mémoire par l'API ; injecter une consigne durable par un contenu de A ; nouvelle conversation ; relire l'état ; supprimer et vérifier.
- Pièges : la mémoire de son propre compte n'est pas un finding.
- Preuve : état de B lu en HTTP avant et après, avec contrôle sans charge.

**C7 `ai-file-upload`** (classe `file-upload`).
- Quand : l'op `upload` existe.
- Techniques : document bénin avec consigne et canari ; URL de la pièce jointe testée par `qq` ; type servi.
- Pièges : fichiers de plus de 256 Kio, charge exécutable.
- Preuve : comme C2 pour l'URL, comme C4 pour l'injection.

**C8 `ai-connectors`**, plan seulement.
- Quand : Mio a activé un connecteur sur user-b.
- Techniques : contenu de A livré dans la source de B, déclenchement par une demande ordinaire.
- Preuve : action visible dans le compte de B ou secret de B vu par A.
- Tant que les prérequis manquent : `bh-note blocked account "connector not enabled"`.

Travaux de terrain pour le second passage : I7, les alias de classe `ai-input-extraction` et `ai-memory`, le type `observation`, et les mesures de B6 et B8 (noms réels des routes et des sélecteurs).

## 8. Questions pour Mio

1. **Périmètre substrate** : réduire aux chemins Copilot (B5) ? Recommandation : oui.
2. **`copilot.com` et `copilot.ai`** : la page MSRC cite `copilot.microsoft.com` et `copilot.ai`. Confirmes-tu que la redirection vers `copilot.com` est couverte ? Recommandation : le noter dans chaque rapport, n'ajouter `copilot.ai` que s'il sert l'appli.
3. **Disponibilité pour les challenges** : combien par chasse, à quelles heures ? Recommandation : chasses de jour, un push par 5 min au plus, l'agent passe en HTTP sinon.
4. **Plafond de prompts** : recommandation 80 par segment et 200 par jour et par compte, tenus en dur (I17).
5. **Comptes** : « MSOBB » est-il dans le nom des deux comptes ? Mémoire activée sur user-b avant Opus ? Recommandation : oui aux deux, connecteurs après la première chasse.
6. **Juge** : Mythos en premier juge quand Opus chasse, Opus quand Mythos chasse ? Recommandation : oui, jamais le modèle du chasseur.
7. **`bh-browse --xss` sur MSRC** : un rendu d'une page avec marqueur est-il un « scanner » ? Recommandation : non (I14).
8. **Hôtes de bruit** : télémétrie refusée ; `ecs.office.com` et `config.edge.skype.com` en `assets` (GET sans identifiants) si leurs requêtes sont des GET ? Recommandation : oui après vérification dans `events.jsonl`. `admin.microsoft.com` et `go.trouter.skype.com` restent refusés.
9. **Donnée d'un tiers** : valides-tu l'arrêt immédiat avec push (I11) et un mail à MSRC écrit par toi ?
10. **`navigator.webdriver`** (doc 18) : mesurer et consigner, ne rien masquer ni ajouter. Recommandation : oui.