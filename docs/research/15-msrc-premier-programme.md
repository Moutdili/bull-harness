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
- **Websockets** : le gate refuse tout websocket (il ne juge pas les trames) et `bh-browse` aussi. Le chat Copilot
  passe probablement par websocket (supposé, à mesurer avec `bh-browse`, ligne « websockets: N refused »). Tant
  que le gate n'a pas de mode websocket borné (à concevoir, décision de Mio), un chat websocket seul est
  injoignable ; chercher un chemin HTTP vers le même assistant.
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
gate. S'il ne parle qu'en websocket (à mesurer), il ne l'est pas aujourd'hui ; voir « Compléments » ci-dessus.
