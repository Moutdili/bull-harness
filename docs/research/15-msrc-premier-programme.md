# 15 — MSRC (Microsoft) comme premier programme (2026-11-25)

Sources lues le 2026-11-25 (agent de lecture, aucune injection repérée) : bounty-programs, bounty-terms,
pentest-rules-of-engagement, zero-day-quest-research-challenge, bounty-guidelines (lue aux 2/3), bounty-ai (Copilot) ;
recherche web sur Zero Day Quest et « In scope by default » (blog MSRC, déc. 2025). Les vidéos de la page seront
transcrites par Mio : à confronter à ce document.

## Peut-on soumettre ?

Oui. Âge ≥ 14 ans ; exclus : pays sous sanctions US, employés et ex-employés Microsoft (6 mois). La Suisse n'est pas
citée comme exclue. Soumission par le MSRC Researcher Portal (étapes, version, PoC, impact). Paiement après formulaire
fiscal (W-8BEN pour un non-Américain) sous 30 jours. Soumissions confidentielles ; code de PoC détaillé retenu 30 jours
après le correctif. Demander un SLA fait perdre l'éligibilité.

## Ce qui contraint le harnais

- **Tester seulement ses propres tenants et comptes** (comptes de test et tenants d'essai encouragés, nom « MSOBB »
  si possible). Jamais les données d'un autre client ni de Microsoft ; au-delà de la PoC, rien.
- **Interdit** : « network-intensive fuzzing or automated testing that generates excessive traffic » (aucun seuil
  publié), DoS, ingénierie sociale, secrets qui ne sont pas les nôtres, post-exploitation. Fuzzing et scan seulement
  sur ses propres VM Azure.
- **IA** : vérifier tout contenu produit par un outil ou une IA avant de soumettre ; un volume de soumissions non
  relues par un humain peut valoir une suspension. Pour Copilot : injection de prompt sans impact sur un autre
  utilisateur et fuite du prompt système : hors périmètre.
- **Barre** : programmes cloud (Azure, Identity, M365, Dynamics) Critique ou Important seulement ; depuis déc. 2025
  (« In scope by default »), tout service en ligne Microsoft est éligible si l'impact est démontré. Copilot paie de
  100 $ à 30 000 $.

## Compléments des vidéos MSRC (transcrites le 2026-11-25)

Sources : T1 « Security Research in Copilot Studio », T2 « Zero Day Quest: … AI Research », T3 « … Red Team AI
Systems Using PyRIT » (2 déc. 2024). Paroles d'orateurs, pas les conditions : les pages officielles priment.
Détail et citations : skills `msrc-ai-bug-bounty` (barre, rapport), `msrc-copilot-studio-research`,
`ai-red-team-pyrit`, et leurs `references/talk-notes.md`.

- **Outil automatisé (T3)** : admis s'il respecte les limites de débit (« abide by the rate limiting that is in
  place »). Aucun seuil publié. Classer un outil d'injection comme « outil de test » sous
  `scanners_allowed: false` est une décision de Mio, à écrire dans le scope (plafond par appel et par jour).
  Contourner la limite de débit : ne pas le chercher ; le signaler si vu par hasard.
- **Exécution côté serveur (T3)** : arrêt à la première preuve ; MSRC demande d'écrire à bounty@microsoft.com
  avant d'aller plus loin (« don't go beyond proof of concept »). Geste harnais : `bh-note blocked other`, piste
  close, Mio décide.
- **Contrats de service (T3)** : utiliser les services « in a way that does not violate our service agreements ».
  Bridage d'un compte de test : arrêt sur cette surface.
- **Champs du rapport IA (T2)** : URL ou application exacte, réglages choisis et texte de chaque prompt, preuves
  (captures, vidéo, identifiant de conversation), taux de reproduction (k/N), si possible preuve que ce n'est pas
  une hallucination. Liens courts entendus (`aka.ms/secure-ai`, `aka.ms/secure-at`) : divergents, non vérifiés,
  ne pas les utiliser ; passer par le portail lié depuis bounty-ai.
- **Donnée d'un tiers vue par accident (T1)** : la signaler tout de suite (« let us know immediately so we can
  contact our customers »). Pendant la chasse : arrêt, aucune relecture, `bh-note blocked other` sans contenu.
  Fait dédié, pause du programme et alerte à Mio : à construire.
- **Websockets** (mis à jour le 2026-11-25) : le gate a un mode websocket borné, activé par `websockets: true` dans
  le scope (refusé sinon) : cibles seulement, handshake jugé comme une requête cible, messages client limités par
  connexion (12/min, 64 Kio, 10 min, 2 connexions ; variables `BH_WS_*` du gate) et journalisés (taille, empreinte,
  extrait caviardé). `scopes/msrc/copilot.yaml` l'active, avec consigne de débit bas. `bh-browse` laisse alors passer
  les websockets vers la cible (ligne « websockets: N opened to the target »). Que le chat Copilot passe par
  websocket reste à mesurer au premier passage live ; s'il a un chemin HTTP, le préférer (plus de contrôles du gate).
- **Hôtes de support** : les hôtes de connexion Microsoft (`login.live.com`…) et d'assets (`res.cdn.office.net`…)
  sont sortis de `in_scope` vers `support` : ils ne sont plus des cibles. `auth` ne sert qu'à l'enrôlement
  (`bh-login`), `assets` est en GET/HEAD sans cookies ni identité (voir `architecture.md` §2). `login.live.com` et
  `login.microsoftonline.com` sont devenus `sso` (ci-dessous).
- **Copilot en usage réel (constat live du 2026-11-25)** : `bh-login` va jusqu'au chat connecté, et sous `user-a` le
  chat s'affiche connecté dans `bh-browse`. Mais l'appli obtient ses jetons d'API par une connexion silencieuse
  (iframe `GET login.microsoftonline.com/9188040d-…/oauth2/v2.0/authorize`, `/savedusers`, puis échange PKCE
  `POST …/oauth2/v2.0/token`), refusée tant que ces hôtes étaient `auth` : sans jeton, aucun appel aux API du chat.
  Le chat passe par `wss://substrate.office.com/…` (et peut-être `wss://substrate.svc.cloud.microsoft/…`), et
  Cloudflare Turnstile (`challenges.cloudflare.com/turnstile/v0/api.js`) protège l'envoi de messages des comptes
  gratuits.
- **Ce qui a changé** (voir `architecture.md` §2) :
  - deux kinds de support. `sso` pour `login.microsoftonline.com` et `login.live.com` : GET/HEAD de tout client, POST
    seulement sur `token_paths` (`/*/oauth2/v2.0/token`, `/oauth20_token.srf`), sous identité les seuls cookies de
    la jarre pour cet hôte, jamais d'en-tête de programme ni d'identité, classe `support`. `passthrough` pour
    `challenges.cloudflare.com` : CONNECT 443, TLS jamais intercepté (options mitmproxy `ignore_hosts` +
    `show_ignored_hosts`), débit et volume bornés, journal hôte + octets + durée ;
  - `substrate.office.com` et `substrate.svc.cloud.microsoft` sont des cibles (« Copilot chat hub (wss), our own
    conversations only ») ;
  - l'enrôlement garde les cookies de `login.microsoftonline.com` (hôte `sso`) ;
  - `bh-browse` pose `X-BH-Identity` requête par requête, vers les cibles et les hôtes `sso` seulement.
- **Ligne éthique sur le challenge (règle de Mio, non négociable)** : on ne casse jamais le challenge. Pas de
  navigateur déguisé (webdriver masqué, plugin stealth, faux user-agent), pas de service de résolution, pas de requête
  qui saute ou rejoue un jeton de challenge, pas de test pour savoir si le serveur le vérifie. On arrête seulement de
  l'empêcher nous-mêmes : pas d'interception TLS sur l'hôte du challenge (l'empreinte TLS vue par Cloudflare est celle
  de Chromium, pas celle de mitmproxy, cf. `10-sessions-anti-bot.md` §4), son script n'est pas bloqué, et le
  challenge décide seul. S'il refuse le navigateur headless de l'agent, c'est un `bh-note blocked captcha` ; un humain
  (Mio) peut le résoudre lui-même dans le navigateur persistant de l'agent (brique P1). Le gate reste la seule
  frontière dure : chaque ouverture est minimale, journalisée et testée.
- **Notes de la page MSRC reprises dans le scope** : la page déclare « copilot.microsoft.com and copilot.ai … when
  tested using a personal account » (`copilot.ai` n'est pas encore une cible du YAML) ; « MSOBB » dans le nom du
  compte si possible ; identifiant de conversation obtenu par `/id` dans la conversation, à joindre au rapport.
- **À valider en live** : jetons obtenus (POST token 200 sous `user-a`, aucun refus `token_paths` ni pré-vol `OPTIONS`
  refusé dans `events.jsonl`), `/savedusers` en GET, websocket substrate ouvert et borné, événement `passthrough` avec
  des octets, aucune requête déchiffrée vers `challenges.cloudflare.com`, et le comportement de Turnstile dans
  `bh-browse` headless (attendu : refus possible, sans contournement).
- **Hors bande** : `bh-oob` n'existe pas (issue 31). Preuve sans récepteur (effet vu depuis le compte A ou chez
  la victime B, à nous) ; à défaut, blocker `oob-needed`. SSRF : la preuve est la requête reçue chez nous, jamais
  une adresse interne.

## Zero Day Quest

Deux volets : un Research Challenge ouvert à tous (+50 % pour un Critique ou un scénario à fort impact, cloud et IA)
et un Live Hacking Event sur invitation (45 chercheurs, sélection par les montants touchés). Dernière édition lue :
challenge du 4 août au 4 octobre 2025, événement au printemps 2026. Aucune édition suivante annoncée dans ce qui a été
lu. Sans challenge ouvert, une soumission suit les programmes normaux.

## Adaptation du harnais (avant le premier run)

| Besoin | Pourquoi | Travail |
|---|---|---|
| Scope MSRC ciblé | « tous les services en ligne » ne se cartographie pas ; le scan intensif est interdit | YAML par service visé (ex. Copilot web), `scanners_allowed: false`, débit bas (1-2 req/s), en-tête d'identification |
| Identités Microsoft | login Entra ID interactif + MFA : la recette JSON de `bh accounts` ne marche pas | Mio crée 2 comptes ou 2 tenants (attaquant / victime) ; nouvelle recette « refresh_token OAuth » pour renouveler les jetons sans humain |
| Pas de scan | `bh-scan`, `bh-content`, `bh-zap --active` interdits ici | déjà géré par `scanners_allowed: false` (refus `[bh-rules]`) ; le verrou d'outils doit accepter crawl seul |
| Anti-bot | services derrière des CDN/WAF, empreinte TLS de mitmproxy | mesure de l'issue 28 avant le premier run |

## Recommandation

Commencer par **Copilot** (copilot.microsoft.com, compte personnel) ou un service Azure précis dans nos tenants :
périmètre net, identité simple, `bh-browse` adapté, impact entre utilisateurs (deux comptes à nous) prouvable par le
juge. Les services cloud larges (Azure, Entra ID) viendront après la recette OAuth.

**Réserve (2026-11-25)** : cette recommandation suppose que le chat Copilot soit joignable à travers le
gate. S'il ne parle qu'en websocket (à mesurer), il passe par le mode websocket borné (voir « Compléments »), à
valider en live avant la première chasse.
