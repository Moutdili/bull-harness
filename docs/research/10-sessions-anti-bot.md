# 10 — Sessions autonomes et protections anti-bot

Compilé le **2026-11-25**. Code lu : `src/bh/gate/addon.py`, `src/bh/scope/model.py`, `src/bh/runner/ingest.py`,
`src/bh/runner/prompt.py`, `src/bh/board/db.py`, `src/bh/agent/note.py`, `src/bh/agent/q.py`, `container/compose.yaml`.
Aucune requête vers une cible. Légende du dossier : ✅ vérifié sur source primaire le 2026-11-25 · ⚠ source tierce
non re-vérifiée · ❓ supposition, à mesurer.

## 1. Résumé

1. Les deux plateformes permettent les comptes de test créés par le chasseur. Les alias email existent : `@intigriti.me` (suffixes `+`/`-` illimités) et `@yeswehack.ninja` (3 alias par défaut, KYC obligatoire). ✅
2. Aucune règle de plateforme trouvée n'interdit en clair le contournement d'un WAF ou d'un captcha. YWH impose de se limiter aux actions « expressly authorized ». On en tire une ligne rouge prudente : on ne résout pas un captcha, on n'achète pas de solveur, on n'utilise pas de numéro SMS virtuel.
3. Inscription, connexion et vérification d'email peuvent tourner sans humain. Un navigateur headless sur l'hôte passe par le gate. L'hôte lit la boîte qui reçoit les mails de l'alias. Le TOTP est généré et gardé sur l'hôte.
4. Point technique clé : la cible ne voit ni curl ni le navigateur. Elle voit la pile TLS et HTTP/2 de mitmproxy, la même pour tous les clients. Le gate réécrit aussi l'UA pour les programmes qui l'imposent. Un UA de navigateur posé sur une empreinte mitmproxy est donc incohérent par construction. ⚠/❓ (à mesurer au lab)
5. L'addon `mitmcloak` (MIT, v0.1.0 du 2026-09-02) donne au gate une empreinte TLS/H2 de navigateur. Il court-circuite toutefois le hook `server_connect`, qui porte notre vérification IP anti-rebinding. On ne l'adopte pas avant un test au lab qui prouve que cette garde tient encore.
6. Quand le mur tient (captcha à chaque requête, SMS, KYC, challenge non passé par un vrai navigateur) : un fait board `wall` par actif, avec un code de raison. L'agent passe à autre chose. Aucune todo humaine.

## 2. Règles des plateformes

### 2.1 YesWeHack

| Sujet | Passage exact | Source | Verdict |
|---|---|---|---|
| Alias email | « All emails sent to this alias address will be automatically forwarded to your actual email address » | [HelpCenter — Email Aliases](https://helpcenter.yeswehack.io/en/articles/369818-email-aliases) ✅ | Permis. Le mail arrive dans la boîte d'inscription YWH de Mio. |
| Alias : nombre, KYC | « KYC verification is required to use this feature. » · « By default, all users have three email aliases that they can enable/disable at any time. » Des alias en plus se demandent au support, programme par programme. | idem ✅ | 3 alias suffisent pour `user-a` et `user-b`. Le format exact et le suffixe `+` ne sont **pas documentés**. ❓ Note : un résumé de recherche annonçait « one alias » ; la page lue dit trois. |
| Alias obligatoire (exemples) | DataDome : « You must use your Yeswehack alias (@yeswehack.ninja) as an e-mail to signup. » · Infomaniak : « please use exclusively your YWH aliases » et « Reuse your existing client accounts as much as possible » · Doctolib : « You can use your YesWeHack email alias (@yeswehack.ninja) to register » | [DataDome](https://yeswehack.com/programs/datadome-bug-bounty), [Infomaniak](https://yeswehack.com/programs/infomaniak-bug-bounty-program), [Doctolib](https://yeswehack.com/programs/doctolib-public-bug-bounty-program) ✅ | Par programme. Réutiliser les comptes, ne pas en recréer à chaque run. |
| Credentials fournis | « Credentials will only be assigned to KYC-verified Hunters. » · « A best practice is to provide 2 test accounts for each Hunter » · « These features are only available on Private Programs » | [HelpCenter — Credentials pool](https://helpcenter.yeswehack.io/en/articles/372760-credentials-pool) ✅ | Voie privilégiée en privé : pas d'inscription du tout. Aucune API hunter documentée pour les récupérer. ❓ |
| Outils et LLM | « Limit testing volume to what is reasonable and maintain control over tools, scanners, payloads, and LLM results. » · « Use scanning and exploitation tools only while explicitly authorized. » | [HelpCenter — Platform code of conduct](https://helpcenter.yeswehack.io/en/articles/396541-platform-code-of-conduct) ✅ | Permis sous contrôle. Le harnais doit rester borné (débit, scope) et chaque finding validé. |
| Slop IA | Violation « Program spamming and AI Slop » : rapports « based on assumptions, AI-generated hypotheses without manual verification ». | idem ✅ | Le vérificateur et la todo `submit` humaine restent obligatoires. |
| Périmètre des actions | « Restrict testing actions to those expressly authorized by the program scope. » | idem ✅ | Base de la ligne rouge captcha/WAF (§4.3). |
| Comptes multiples | « Bypassing sanctions via multiple accounts creation is strictly forbidden. » | idem ✅ | Vise les comptes **plateforme**, pas les comptes de test sur la cible. |
| Ingénierie sociale | « Attacks by social engineering are strictly forbidden, unless otherwise stated in the program rules » | idem ✅ | Pas de faux support, pas de faux dossier KYC. |
| Captcha / anti-bot | Doctolib et Infomaniak classent l'absence de captcha ou de rate-limit en non qualifiant. DataDome classe « Bot detection capability » en non qualifiant. | pages programmes ✅ | Les programmes ne disent rien sur le *passage* d'un captcha. Aucune autorisation explicite trouvée. |
| UA imposé | Infomaniak : User-Agent « must be set to `Infomaniak-YWH-Bugbounty` ». Doctolib : « append to your user-agent header the following value: 'BugBounty/42 (YWH)' ». | pages programmes ✅ | Attention : Doctolib dit **ajouter**. Le gate **remplace** l'UA (`addon.py`, `req.headers["User-Agent"] = scope.user_agent`). Voir §4.2. |

### 2.2 Intigriti

| Sujet | Passage exact | Source | Verdict |
|---|---|---|---|
| Alias | « yournickname@intigriti.me will forward all mails to your registered e-mail address at intigriti. » · « You can use wildcards in your intigriti.me address by adding a + or a - sign behind your nickname with any combination. » · « This enables you to create multiple test accounts on a program » | [KB — intigriti.me email alias](https://kb.intigriti.com/en/articles/2642598-intigriti-me-email-alias) ✅ | Permis. Alias illimités `pseudo+<n>@intigriti.me`. |
| Alias obligatoire | « If a program requires the use of intigriti.me, it means that you will need to use your personal e-mail alias to sign up. » · « Some programs demand that you are setting a custom header or user agent on every single request » | [KB — Understanding testing requirements](https://kb.intigriti.com/en/articles/5412984-understanding-testing-requirements) ✅ | Par programme. Le gate injecte déjà les en-têtes requis. |
| Comptes de test | « we ask you to limit your testing strictly to your own (test) accounts and not to target accounts of other persons. » | [KB — Community code of conduct](https://kb.intigriti.com/en/articles/5247238-community-code-of-conduct) ✅ | Permis et attendu. |
| Comptes multiples | « Trying to evade or bypass our sanctions, for example by creating multiple accounts, is not permitted » | idem ✅ | Vise la plateforme, comme chez YWH. |
| Automatisation | « Be gentle when conducting automated tests or scanners. » · « Some programs may disallow automated testing of any kind, or impose rate limits. » | idem ✅ | Par programme. Déjà couvert par `automation_allowed`. |
| IA | « The use of AI tools is permitted and encouraged when used responsibly as part of a hacker's workflow. » · « Be open and transparent about the use of AI. Disclose when and how AI was used in your submission. » | idem ✅ | Permis. **Divulgation obligatoire** dans chaque rapport Intigriti. À ajouter au gabarit de PoC. |
| Tiers | §10.3.5 : « You may not store or host Company Data on third party systems » | [KB — Researcher T&C](https://kb.intigriti.com/en/articles/5466165-researcher-terms-conditions) ✅ | Argument contre les solveurs de captcha et les boîtes jetables tierces. Le captcha et le mail de la cible sont des données de la cible (interprétation ❓). |
| Disruption | §6.3 : « you do not intervene with the effective functioning of the Assets » | idem ✅ | Pas de création de comptes en masse. |
| WAF / captcha | Ni le code de conduite ni les T&C n'en parlent (vérifié). | idem ✅ | À lire programme par programme. |

### 2.3 Synthèse

- **Permis partout** : créer ses propres comptes de test, avec l'alias quand le programme l'exige. Automatiser sous les limites du programme. Utiliser une IA, avec divulgation chez Intigriti.
- **Interdit partout** : ingénierie sociale, DoS, toucher aux comptes des autres, multi-comptes plateforme.
- **Non tranché par les plateformes → ligne rouge interne** : résoudre ou faire résoudre un captcha. Utiliser un numéro SMS virtuel ou loué. Usurper une identité pour un KYC. Retirer l'en-tête d'identification imposé pour passer un WAF.
- **À vérifier par programme** : alias obligatoire, réutilisation des comptes, UA à *ajouter* ou à *remplacer*, mention explicite d'une IP ou d'un en-tête allowlisté.

## 3. Sessions autonomes

### 3.1 Existant (✅ lu dans le code)

- Une identité est un fichier `var/state/identities/<programme>/<nom>.json` de forme `{"headers": {...}}`. Le gate le relit à chaque requête qui porte `X-BH-Identity` (`addon.py`, `_apply_identity`).
- Le YAML de scope ne contient que `{name, secret_ref}` (`model.py`, champ `identities`).
- Le gate ne garde aucun cookie renvoyé par la cible. Un `Set-Cookie` qui fait tourner la session n'est pas réécrit. La session devient donc vite périmée sur les sites qui la font tourner.
- Un 401 sous identité produit un événement `auth`. `ingest.gate_events` en fait une todo humaine `auth` après `AUTH_TODO_THRESHOLD` réponses. Un challenge produit une todo `waf`.
- L'agent ne monte pas `var/state` : il ne voit jamais les sessions. On garde ce principe.

### 3.2 Inscription et connexion par navigateur headless

- Le navigateur tourne dans un conteneur `browser` séparé, sur le réseau `sandbox`, avec `HTTPS_PROXY=gate:8080`. Il passe donc par le scope, le débit et les journaux. Le choix du moteur (Playwright, Patchright, Camoufox…) relève de l'agent « navigateur » du swarm.
- Il est piloté par l'**hôte**, pas par l'agent. Il écrit la session dans `var/state/identities/`. L'agent ne la lit jamais.
- Une recette par programme, décrite dans le YAML de scope : URL d'inscription, URL de connexion, URL sonde (`/api/me`) et statut attendu. Les sélecteurs de formulaire sont trouvés par le navigateur (vision) ou déclarés.
- Le résultat est extrait après la connexion : cookies du domaine (`context.cookies()`), et `Authorization: Bearer` capturé sur la première requête API authentifiée. Le jeton peut aussi venir de `localStorage`.
- CSRF : jeton par requête. Il est lisible par l'agent dans les réponses et n'ouvre rien seul. L'agent le recopie lui-même. Le gate ne le gère pas. Exception : le double-submit cookie, déjà couvert par la jarre de cookies.

### 3.3 Stockage

| Donnée | Où | Qui lit |
|---|---|---|
| Mot de passe, secret TOTP, alias utilisé | `secrets/identities/<programme>/<nom>.json` (0600, hôte) | hôte et conteneur `browser`, pendant le login seulement |
| Session (en-têtes, cookies, expiration) | `var/state/identities/<programme>/<nom>.json` (existant, étendu) | gate |
| Événements de session | `events.jsonl` du gate (existant) | runner |

Le fichier de session gagne trois champs : `cookies` (jarre par domaine), `expires_at`, `probe` (`{url, status}`). `headers` reste lu tel quel : rétrocompatible.

### 3.4 Renouvellement et session morte

- **Jarre dans le gate** : sur une réponse à une requête sous identité, le gate fusionne les `Set-Cookie` du domaine en scope dans le fichier de session. Écriture atomique (`rename`). Cela couvre la rotation des cookies et `__cf_bm`.
- **Détection** (événement `session-dead`) : 401 sous identité, 302 vers une URL de login déclarée, ou réponse à la sonde différente du statut attendu. Le seuil reste bas, car un 401 peut aussi être un résultat de test.
- **Renouvellement** : le runner reçoit `session-dead`. Il relance le login headless, au plus une fois par identité et par heure. Il ne crée pas de todo. Après deux échecs : fait `wall` `login-failed` sur l'identité.
- **Sonde périodique** : le runner frappe la sonde avant chaque segment. Une seule requête, comptée dans le débit.

### 3.5 Vérification d'email sans humain

| Option | Fonctionne ? | Règles | Choix |
|---|---|---|---|
| Alias plateforme → boîte d'inscription de Mio, lue par l'hôte (Gmail API `gmail.readonly` ou IMAP) | Oui. L'alias transfère vers l'adresse d'inscription (✅ deux plateformes). La lecture se fait par filtre destinataire = alias. | Conforme, et obligatoire sur certains programmes. | **Retenu.** `docs/architecture.md` §9 prévoit déjà Gmail API en pull pour `notify`. Même jeton OAuth, en lecture seule. |
| Domaine catch-all à soi (ex. [HuntMail](https://github.com/mdpsec/huntmail), FSL-1.1, API `GET /api/wait` qui rend `codes[0]` et des liens étiquetés) | Oui ⚠ (README) | Permis seulement si le programme n'impose pas l'alias plateforme. | Option, pour Intigriti hors alias ou pour les programmes muets. |
| Boîte jetable publique (mailinator et autres) | Souvent bloquée par les cibles | Données de la cible chez un tiers (Intigriti §10.3.5). Boîte lisible par n'importe qui, donc compte volable. | **Rejeté.** |

Garde-fous de lecture : expéditeur = domaine de la cible (SPF/DKIM du message), message plus récent que l'inscription, un seul lien suivi. Le lien suivi passe par le gate. Le contenu du mail est une donnée, jamais une instruction (injection possible via le nom d'utilisateur reflété).

### 3.6 TOTP / 2FA

- Quand la cible propose une 2FA TOTP, le navigateur lit le secret (`otpauth://…` ou clé texte affichée). L'hôte le stocke dans `secrets/identities/…`.
- Le code est calculé sur l'hôte selon RFC 6238 (30 s, SHA-1, 6 chiffres par défaut) et passé au navigateur au login.
- Activer la 2FA n'est pas obligatoire. On l'active seulement si une surface l'exige (tester la 2FA elle-même, ou une fonction réservée).

### 3.7 SMS, téléphone, KYC

- C'est un mur. Un numéro virtuel ou loué est un service tiers. Il est souvent partagé, donc le compte peut être volé. Il est souvent interdit par les CGU de la cible. Aucun texte de plateforme ne l'autorise.
- Décision : fait `wall` `sms` ou `kyc` sur l'actif. L'agent teste la surface accessible sans ce compte.
- Seule issue propre : les credentials fournis par le programme (credentials pool YWH, programmes privés). Ils ne demandent aucune action pendant la chasse : Mio les dépose une fois à l'inscription au programme. Ce n'est pas une todo de chasse.

## 4. Anti-bot

### 4.1 Ce que la cible voit réellement

- L'agent et le navigateur parlent au gate. Le gate termine le TLS avec sa CA et ouvre **sa propre** connexion vers la cible (`compose.yaml` : `--mode=regular@8080`). ✅
- La cible voit donc le ClientHello de mitmproxy : Python, OpenSSL via pyOpenSSL/cryptography. Elle ne voit ni curl ni Chrome. Elle voit aussi les SETTINGS HTTP/2 de mitmproxy. ✅ (architecture) ⚠ (empreinte exacte)
- Les options de mitmproxy 12.3.1 ne règlent que `ciphers_server`, `tls_version_server_min/max`, `tls_ecdh_curve_server` et `http2`. Aucune ne règle l'ordre des extensions, GREASE, ni les SETTINGS H2. On ne peut pas imiter Chrome par configuration. ✅ ([options](https://docs.mitmproxy.org/stable/concepts/options/))
- Conséquence 1 : `curl_cffi` ou `curl-impersonate` **dans l'agent** ne servent à rien. Le gate refait le TLS. ✅ (déduction de l'architecture)
- Conséquence 2 : tous nos clients sortent avec la même empreinte et la même IP. Un cookie de challenge obtenu par le navigateur et rejoué par `q` reste cohérent côté réseau. ❓ à mesurer.
- Conséquence 3 : un UA Chrome sur une empreinte mitmproxy est incohérent. Cloudflare compare les deux ([cité dans selenium-wire #215](https://github.com/wkeeling/selenium-wire/issues/215)) ⚠. Le README de mitmcloak rapporte que Chromium headless change de JA4 en passant par mitmproxy ⚠.
- Conséquence 4 : quand le programme impose un UA (`Infomaniak-YWH-Bugbounty`), le gate l'impose à tous. La cohérence UA/TLS est alors perdue d'office. C'est voulu par le programme : son WAF peut nous reconnaître par cet UA. Un blocage malgré l'UA imposé est un mur, pas un problème à contourner.

### 4.2 Catalogue

| Mécanisme | Signal | Contre-mesure possible | Permis ? |
|---|---|---|---|
| Empreinte TLS JA3/JA4 | ClientHello : suites, extensions, ordre, ALPN. Cloudflare l'expose en `cf.bot_management.ja4`, Enterprise + Bot Management seulement ✅ ([doc](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/)) | Sortie du gate avec une empreinte de navigateur (mitmcloak / httpcloak). | Oui à condition de garder l'en-tête ou l'UA d'identification exigé. On veut une empreinte cohérente, pas l'anonymat. ❓ interprétation |
| Empreinte HTTP/2 (« Akamai H2 ») | SETTINGS, WINDOW_UPDATE, ordre des pseudo-en-têtes | Même outil (httpcloak la reproduit ⚠). | Idem |
| En-têtes et ordre | Ordre et présence de `sec-ch-ua`, `accept-language`… | Navigateur réel. Mode `merge` de mitmcloak. | Oui |
| `__cf_bm` (Cloudflare) | Cookie de gestion des bots. « expires after 30 minutes of continuous inactivity » ✅ ([doc cookies](https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/)) | Jarre de cookies du gate (§3.4). | Oui : c'est accepter un cookie. |
| `cf_clearance` (challenge JS, Turnstile) | « stores the proof of challenge passed ». Lié « to the specific visitor and device » ✅ ([pre-clearance](https://developers.cloudflare.com/turnstile/get-started/pre-clearance/)). Durée par défaut 30 min, réglable ✅. Lien IP + UA + JA3 ⚠ (blog tiers seulement). | Navigateur réel par le gate. Le challenge s'exécute normalement. Cookie repris par `q` via la jarre de l'identité. | Oui pour un challenge **non interactif** que le navigateur passe seul. Non pour un captcha à cliquer ou une image à résoudre. |
| Akamai `_abck` | Cookie validé après POST de `sensor_data` (télémétrie JS) ⚠ (sources de vendeurs de contournement) | Navigateur réel, puis jarre. Ne jamais générer `sensor_data` à la main. | Navigateur : oui. Forger le capteur : **non** (contournement actif). |
| DataDome (`datadome`, `captcha-delivery.com`) | Score par requête. Captcha servi par `captcha-delivery.com` ⚠ | Navigateur réel, puis jarre. Un captcha servi = mur. | Idem. Le gate détecte déjà `captcha-delivery.com`. |
| PerimeterX / HUMAN (`_px3`, `px-captcha`) | Capteur JS, puis cookie `_px3` ⚠ | Navigateur réel. « Press & hold » = mur. | Idem |
| Turnstile | Widget, souvent non interactif | Navigateur réel. | Oui s'il passe seul. Sinon mur. |
| reCAPTCHA v2 / hCaptcha | Puzzle humain | Aucune. | **Non** : résoudre ou payer un solveur n'est pas « expressly authorized ». Le défi part aussi chez un tiers. |
| reCAPTCHA v3 | Score invisible | Navigateur réel. Un score bas = refus côté cible = mur. | Oui en passif. |
| Allowlist par IP ou en-tête du programme | En-tête ou UA imposé | Déjà injecté par le gate. | Oui : c'est **la** voie prévue. |

### 4.3 Options étudiées pour la sortie TLS du gate

| Option | Faisabilité chez nous | Maturité | Risque règles | Avis |
|---|---|---|---|---|
| curl_cffi / curl-impersonate dans l'agent | Inutile : le gate refait le TLS. | curl_cffi 0.17.0 (2026-10-26), curl-impersonate 2.0.0 ⚠ | Nul | Rejeté |
| `mitmcloak` : addon mitmproxy qui lit le ClientHello du client (`tls_clienthello`) et la préface H2 (`next_layer`), puis rejoue la requête via httpcloak dans le hook `request` ([repo](https://github.com/sardanioss/mitmcloak), MIT) | Possible. Il se charge **en dernier**, après `addon.py`. Mode `static` (préréglage Chrome) ou `mirror` (copie l'empreinte du client). | v0.1.0 du 2026-09-02, 35 commits, 74 étoiles. httpcloak 1.7.4 du 2026-11-14 (PyPI ✅). Jeune. | Faible si l'UA imposé reste en place. | **À tester au lab seulement.** Bloquant : « `serverconnect` and `serverconnected` hooks do not fire on bridged flows » (README ⚠). Notre `server_connect` vérifie et épingle l'IP (anti-rebinding). httpcloak résout lui-même. Il faut d'abord prouver que la garde IP tient (vérification à refaire dans `request`, ou résolution forcée). Autres limites annoncées : websockets non pontés (on les refuse déjà), corps bufferisés, Alpine/musl non supporté. |
| Proxy uTLS en aval du gate (`impersonate-proxy`, Go, MIT, 0 étoile sur le fork lu) | Mauvais. En mode upstream, mitmproxy voit l'adresse du proxy : notre vérification IP par hôte saute. Le proxy refait aussi un MITM, donc une CA de plus. | Faible | Faible | Rejeté |
| Navigateur réel par le gate, cookies repris par `q` | Oui. Même IP, même empreinte de sortie que `q`. L'UA est réécrit par le gate de façon identique (❓ cohérence avec le `navigator.userAgent` vu par le JS du challenge). | Outils mûrs (Playwright, Patchright 1.64.4, Camoufox 0.5.9 sur PyPI ✅) | Faible pour un challenge passif | **Retenu**, en priorité sur mitmcloak. |
| Solveur de captcha (service payant, modèle de vision) | Techniquement possible | — | Élevé : défait un contrôle de la cible sans autorisation. Données chez un tiers. | **Interdit** par la politique interne. |

### 4.4 Mesures à faire avant toute décision (lab, sans cible réelle)

1. Monter un écho JA4 / Akamai-H2 dans le réseau `lab` (serveur local). Mesurer l'empreinte de `q` via le gate, sans et avec mitmcloak. Critère : JA4 ≠ Chrome sans mitmcloak, JA4 = préréglage Chrome avec.
2. Avec mitmcloak chargé, viser au lab un nom qui se résout vers une IP interdite. Critère : refus du gate. Sinon mitmcloak est exclu.
3. Mesurer si le challenge passif d'un vendeur passe avec l'UA du programme réécrit par le gate. Ce test n'est possible que sur une cible qui l'autorise explicitement (ex. le programme DataDome YWH, qui fournit un compte d'essai). Sinon : supposition non testée.

## 5. Architecture proposée et plan d'intégration

### 5.1 Qui fait quoi

| Composant | Rôle | Ne fait jamais |
|---|---|---|
| **agent** | Teste. Demande une identité par son nom. Écrit un fait `wall` quand il bute. | Lire une session ou un secret. Remplir un formulaire de login. Créer une todo `auth`/`waf`/`account`. |
| **gate** | Injecte la session. Tient la jarre de cookies par identité. Émet `session-dead` et `waf`. (Option lab : empreinte de sortie navigateur.) | Résoudre un challenge. Retirer un en-tête imposé. |
| **browser** (nouveau conteneur, `sandbox`, proxy = gate) | Inscription, login, passage d'un challenge passif. Export cookies et Bearer. | Résoudre un captcha. Être piloté par l'agent. |
| **hôte** (`bh accounts`) | Orchestre l'inscription. Lit la boîte (alias). Calcule le TOTP. Stocke les secrets. Relance le login sur `session-dead`. | Ouvrir une todo humaine pour une session. |
| **runner** | Transforme `session-dead` en relance de login et les échecs en faits `wall`. Retire les todos `auth`/`waf`/`account` du chemin de chasse. | — |

### 5.2 Flux d'une inscription autonome

1. Le runner démarre un programme. `scope.identities` déclare `user-a` et `user-b`, sans session valide.
2. L'hôte choisit l'alias : `pseudo+bh-<prog>-a@intigriti.me` chez Intigriti, un des 3 alias YWH sinon. Il tire un mot de passe aléatoire. Il écrit `secrets/identities/<prog>/user-a.json`.
3. Il lance le conteneur `browser` avec la recette du scope. Le navigateur ouvre l'URL d'inscription via le gate.
4. Un challenge passif passe seul : on continue. Un captcha interactif, un SMS ou un KYC : fait `wall` et arrêt pour cet actif.
5. Le formulaire est soumis. L'hôte attend le mail (Gmail API, filtre `to:<alias>`, expéditeur = domaine en scope, ≤ 10 min). Il en extrait le lien ou le code.
6. Le navigateur suit le lien via le gate. Il se connecte. Il active la 2FA si la recette l'exige ; le secret part chez l'hôte.
7. Il exporte cookies et Bearer. L'hôte écrit `var/state/identities/<prog>/user-a.json` (`headers`, `cookies`, `expires_at`, `probe`).
8. Sonde : `GET probe.url` sous `X-BH-Identity: user-a`. Statut attendu → identité prête, fait `recon` « identity user-a ready ».
9. Même chose pour `user-b`. L'agent démarre et voit `Identities: user-a, user-b`.
10. Pendant la chasse : le gate fusionne les `Set-Cookie`. Une session morte émet `session-dead`. Le runner relance l'étape 6 au plus une fois par heure. Deux échecs : `wall login-failed`.

### 5.3 Format du fait de mur

- Ne pas réutiliser `blocked`. `Board.frontier` (`db.py` l. 302) ne garde que le **dernier** fait `blocked`. Un mur par actif y serait effacé.
- `dead-end` existe déjà côté agent (`note.py`, `FACT_KINDS`). Il est libre et ne se filtre pas par code.
- Proposition : nouveau kind `wall`. Titre `WALL <code> <hôte>[ <chemin>]`. Codes fermés : `captcha`, `sms`, `kyc`, `challenge`, `login-failed`, `paid`, `invite-only`. Résumé : la preuve (flow id du gate, statut, marqueur détecté).
- Commande agent : `bh-note wall <code> <url> -e <flow>`. Le runner l'écrit aussi depuis `waf` et `session-dead`.
- `frontier` liste les murs. Le prompt dit : « un actif en `wall` ne se re-teste pas en authentifié, passe à une autre surface ».
- Un mur expire après 7 jours ou à un `bh scope sync` qui change l'actif. Ainsi un challenge temporaire ne condamne pas un actif pour toujours.

### 5.4 Plan de swarm (un fichier, un propriétaire, critère binaire)

À coordonner avec l'agent « navigateur » (propriétaire de `container/browser/`) et l'agent « humain hors boucle » (propriétaire de `prompt.py` et `ingest.py` dans son plan). En cas de conflit, son plan prime sur ces deux fichiers. Ordre de merge = ordre du tableau.

| # | Fichier | Propriétaire | Tâche | Critère d'acceptation |
|---|---|---|---|---|
| 1 | `src/bh/scope/model.py` | H1 | Identité : `signup_url`, `login_url`, `probe {url,status}`, `alias_slot`, `mfa: none / totp`. Toujours aucun secret. | `pytest tests/test_scope*.py` vert. Un champ `password` dans le YAML lève `ScopeError`. |
| 2 | `src/bh/gate/session.py` (nouveau) | H2 | Jarre par identité : fusion `Set-Cookie` du domaine en scope, écriture atomique. Détection `session-dead` (401, 302 vers `login_url`). | Test : un `Set-Cookie` sous identité met à jour le fichier. Un `Set-Cookie` hors scope ou sans identité ne le touche pas. |
| 3 | `src/bh/gate/addon.py` | H2 | Appelle `session.py` dans `request`/`response`. Injecte `cookies` en plus de `headers`. | Tests gate existants verts. Une requête sous identité porte le cookie de la jarre. L'agent ne voit jamais `Set-Cookie` d'identité dans `flows/` (redaction). |
| 4 | `src/bh/accounts/mail.py` (nouveau) | H3 | Lecture seule Gmail API ou IMAP. `wait(alias, sender_domain, since, timeout)` renvoie lien ou code. | Test sur boîte factice : bon mail trouvé. Expéditeur hors domaine ignoré. Délai dépassé → `None`. |
| 5 | `src/bh/accounts/totp.py` (nouveau) | H3 | RFC 6238. | Vecteurs de test de la RFC 6238 annexe B : tous égaux. |
| 6 | `src/bh/accounts/enroll.py` (nouveau) | H4 | Orchestration §5.2 étapes 2 à 8. Appelle le conteneur `browser`. Écrit les fichiers secrets (0600) et la session. | Lab Juice Shop : `bh accounts enroll lab-juiceshop user-a` finit avec la sonde `/rest/user/whoami` authentifiée, sans action humaine. |
| 7 | `src/bh/cli.py` | H4 | `bh accounts enroll`, `refresh`, `ls`. Retire le message « create test accounts with your alias » (l. 93). | `bh accounts ls` n'affiche aucun secret (grep du mot de passe dans la sortie = vide). |
| 8 | `src/bh/board/db.py` | H5 | Kind `wall`, expiration 7 j, liste dans `frontier`. | Deux `wall` sur deux hôtes apparaissent tous les deux dans `frontier`. |
| 9 | `src/bh/agent/note.py` | H5 | `bh-note wall <code> <url>`. Codes fermés. | Code inconnu → code de sortie ≠ 0. |
| 10 | `src/bh/runner/ingest.py` | H6 | `waf` → `wall challenge`. `session-dead`/`auth` → relance `enroll.refresh`. Plus de todo `auth`/`waf`/`account`. | `grep -n 'add_todo("auth\|add_todo("waf\|add_todo("account' src/bh/runner` = vide. Les tests d'ingestion vérifient les murs. |
| 11 | `src/bh/runner/prompt.py` | H6 | Ligne 60 remplacée par la règle `wall`. Ligne 103 : plus de « ask via a todo ». | `grep -c 'bh-note todo auth' src/bh/runner/prompt.py` = 0. |
| 12 | `docs/architecture.md` (§8) | H6 | Table des todos : `auth`/`waf`/`account` retirés, `wall` décrit. | Relecture Mio. |
| 13 | `src/bh/gate/egress_fp.py` (option, après mesures §4.4) | H2 | Chargement conditionnel de mitmcloak en mode `static`, avec re-vérification IP. | Mesures §4.4 points 1 et 2 vertes. Sinon la tâche est abandonnée. |

## 6. Incertitudes

1. **Lien du `cf_clearance` à l'UA et au JA4.** Cloudflare dit seulement « tied to the specific visitor and device ». Le lien IP + UA + JA3 vient d'un blog tiers. Le transfert navigateur → `q` est cohérent chez nous côté réseau. Il est **non mesuré**.
2. **UA imposé contre challenge JS.** Le gate réécrit l'en-tête UA, mais le JS du challenge lit `navigator.userAgent`. Le vendeur peut voir les deux différer et refuser. Il faudra peut-être faire porter l'UA imposé par le navigateur lui-même. À mesurer sur une cible qui l'autorise.
3. **Alias YWH.** Format, suffixe `+` et nombre réel (trois selon la page lue) ne sont pas documentés au-delà du help center. Aucune API hunter n'est documentée pour les lister. L'exemple de serveur MCP communautaire est non officiel.
4. **mitmcloak et notre garde IP.** L'absence de `server_connect` sur les flux pontés est annoncée par le README, pas vérifiée. Projet de deux mois et demi.
5. **Statut réglementaire du contournement passif.** Aucune plateforme ne dit si imiter l'empreinte d'un navigateur est permis. Notre position (permis si l'identification exigée reste en place) est une **interprétation**. Elle mérite une question au support YWH et Intigriti avant le premier programme protégé.
6. **Empreinte exacte de mitmproxy 12.3.1.** Rapportée différente de celle des navigateurs (test litport sur mitmproxy 9 ⚠, README mitmcloak ⚠). Non mesurée chez nous.

## 7. Sources

Plateformes (✅ lues le 2026-11-25) :
- YesWeHack — [Email Aliases](https://helpcenter.yeswehack.io/en/articles/369818-email-aliases) · [Credentials pool](https://helpcenter.yeswehack.io/en/articles/372760-credentials-pool) · [Platform code of conduct](https://helpcenter.yeswehack.io/en/articles/396541-platform-code-of-conduct) · [LLM, agentic CLIs and MCP for hunters (2026-06-18)](https://www.yeswehack.com/learn-bug-bounty/llm-bug-bounty-hunting-agentic-cli)
- Programmes YWH — [DataDome](https://yeswehack.com/programs/datadome-bug-bounty) · [Infomaniak](https://yeswehack.com/programs/infomaniak-bug-bounty-program) · [Doctolib](https://yeswehack.com/programs/doctolib-public-bug-bounty-program)
- Intigriti — [intigriti.me email alias](https://kb.intigriti.com/en/articles/2642598-intigriti-me-email-alias) · [Understanding testing requirements](https://kb.intigriti.com/en/articles/5412984-understanding-testing-requirements) · [Community code of conduct](https://kb.intigriti.com/en/articles/5247238-community-code-of-conduct) · [Researcher T&C](https://kb.intigriti.com/en/articles/5466165-researcher-terms-conditions)

Technique :
- mitmproxy — [Options](https://docs.mitmproxy.org/stable/concepts/options/) ✅ · version 12.3.1 du 2026-10-25 (PyPI JSON ✅)
- Cloudflare — [Cookies](https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/) ✅ · [Turnstile pre-clearance](https://developers.cloudflare.com/turnstile/get-started/pre-clearance/) ✅ · [JA3/JA4 fingerprint](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/) ✅ · [Clearance](https://developers.cloudflare.com/cloudflare-challenges/concepts/clearance/) ⚠ (lu via résumé de recherche)
- [mitmcloak](https://github.com/sardanioss/mitmcloak) (README ⚠, PyPI ✅) · [httpcloak](https://github.com/sardanioss/httpcloak) (PyPI ✅) · [curl_cffi](https://github.com/lexiforest/curl_cffi) · [curl-impersonate](https://github.com/lexiforest/curl-impersonate) · [impersonate-proxy](https://github.com/Macawls/impersonate-proxy) ⚠ · [hazetunnel](https://github.com/daijro/hazetunnel) (PyPI : 2.0.1 du 2024-06-09, non maintenu en apparence ⚠)
- [selenium-wire #215](https://github.com/wkeeling/selenium-wire/issues/215) ⚠ · [litport — TLS fingerprinting through a proxy](https://litport.net/blog/tls-fingerprinting-through-a-proxy-99688) ⚠
- Akamai / DataDome / PerimeterX : [Scrapfly — Akamai `_abck`](https://scrapfly.io/blog/posts/akamai-bot-manager-understanding-abck-cookies-and-sensor-data) ⚠ · [Scrappey — vendor detection cheatsheet](https://scrappey.com/qa/anti-bot/anti-bot-vendor-detection-cheatsheet) ⚠. Ce sont des vendeurs de contournement : mécanismes à prendre comme indicatifs.
- Boîte catch-all : [HuntMail](https://github.com/mdpsec/huntmail) ⚠ (FSL-1.1-ALv2)

Commandes de preuve reproductibles :
- Versions PyPI : `curl -s https://pypi.org/pypi/<paquet>/json` pour `mitmcloak`, `httpcloak`, `curl-cffi`, `mitmproxy`, `camoufox`, `patchright`, `nodriver`, `hazetunnel` (2026-11-25).
- Code : `grep -rn -i identit src/bh` ; `sed -n 331,460p src/bh/gate/addon.py` ; `sed -n 108,180p src/bh/runner/ingest.py` ; `sed -n 290,320p src/bh/board/db.py`.
