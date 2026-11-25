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
