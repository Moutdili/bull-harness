# Tâches suivies (en attendant les issues GitHub)

Une tâche = un fichier, labels dans l'en-tête. `status` : `open`, `doing`, `done`. Quand le token GitHub aura
les droits « Issues », `github-import.sh` crée les mêmes labels et issues sur le dépôt.

Labels : priorité `P0` (avant le premier run YWH) / `P1` / `P2` · domaine `area:*` · propriétaire `owner:claude|hermes|mio` ·
nature `measure` (mesurer avant de décider), `build`, `research-check` (doctrine vs littérature), `audit`.

## P0

| # | Tâche | Labels | Statut |
|---|---|---|---|
| 1 | [Mesurer un segment long sur le lab (100 tours)](001-mesurer-un-segment-long-sur-le-lab-100-tours.md) | `area:tokens` `owner:claude` `measure` | open |
| 2 | [Vérifier le TTL du cache de prompt en OAuth (5 min ou 1 h)](002-verifier-le-ttl-du-cache-de-prompt-en-oauth-5-min.md) | `area:tokens` `owner:claude` `measure` | open |
| 3 | [Isoler le juge dans son propre conteneur](003-isoler-le-juge-dans-son-propre-conteneur.md) | `area:verify` `owner:claude` `build` | open |
| 4 | [Lab d'injection de prompt contre le chasseur et le juge](004-lab-d-injection-de-prompt-contre-le-chasseur-et-le.md) | `area:gate` `owner:claude` `build` | open |
| 5 | [Reconstruire l'image agent depuis la base épinglée](005-reconstruire-l-image-agent-depuis-la-base-epinglee.md) | `area:ops` `owner:hermes` `build` | open |
| 6 | [Lire les règles hunter YWH sur l'automatisation et l'IA](006-lire-les-regles-hunter-ywh-sur-l-automatisation-et.md) | `area:scope` `owner:mio` `research-check` | open |
| 7 | [Run sur l'app perso de Mio (6.1)](007-run-sur-l-app-perso-de-mio-6-1.md) | `area:ops` `owner:claude` `owner:mio` `build` | open |
| 8 | [Audit Mythos du plan, de la doctrine et du code](008-audit-mythos-du-plan-de-la-doctrine-et-du-code.md) | `area:verify` `owner:claude` `owner:mio` `audit` | open |
| 9 | [Choisir le premier programme YWH](009-choisir-le-premier-programme-ywh.md) | `area:scope` `owner:mio` | open |
| 24 | [Outil bh-browse : navigateur headless dans l'agent](024-outil-bh-browse-navigateur-headless-dans-l-agent.md) | `area:autonomy` `owner:claude` `build` | open |
| 25 | [Comptes de test autonomes (bh accounts)](025-comptes-de-test-autonomes-bh-accounts.md) | `area:autonomy` `owner:claude` `build` | open |
| 26 | [Jarre de cookies et session morte dans le gate](026-jarre-de-cookies-et-session-morte-dans-le-gate.md) | `area:gate` `owner:claude` `build` | open |
| 27 | [Validation live du swarm autonomie](027-validation-live-du-swarm-autonomie.md) | `area:ops` `owner:claude` `owner:mio` `measure` | open |

## P1

| # | Tâche | Labels | Statut |
|---|---|---|---|
| 10 | [Masquage des anciennes observations ou rotation sur seuil de contexte (4.2b)](010-masquage-des-anciennes-observations-ou-rotation-su.md) | `area:tokens` `owner:claude` `build` | open |
| 11 | [Budget par piste et abandon chiffré](011-budget-par-piste-et-abandon-chiffre.md) | `area:autonomy` `owner:claude` `build` | open |
| 12 | [Routage de modèle par segment (cartographie légère, exploitation forte)](012-routage-de-modele-par-segment-cartographie-legere.md) | `area:tokens` `owner:claude` `build` | open |
| 13 | [Sommeil quota calé sur l'heure de reset](013-sommeil-quota-cale-sur-l-heure-de-reset.md) | `area:autonomy` `owner:claude` `build` | closed |
| 14 | [Métrique « soumissions valides »](014-metrique-soumissions-valides.md) | `area:verify` `owner:claude` `build` | open |
| 15 | [Jokers en milieu de label et suffixes publics (0.2b)](015-jokers-en-milieu-de-label-et-suffixes-publics-0-2b.md) | `area:scope` `owner:claude` `build` | closed |
| 16 | [Remettre docs/TODO.md à jour](016-remettre-docs-todo-md-a-jour.md) | `area:docs` `owner:claude` | closed |
| 17 | [Réévaluer la phase 2 (alias, calibrage, mineur)](017-reevaluer-la-phase-2-alias-calibrage-mineur.md) | `area:tokens` `owner:claude` `research-check` | closed |
| 28 | [Mesures anti-bot sur le lab](028-mesures-anti-bot-sur-le-lab.md) | `area:gate` `owner:claude` `measure` | open |
| 29 | [Outil bh-js : bundles JS et source maps (REA en CLI)](029-outil-bh-js-bundles-js-et-source-maps-rea-en-cli.md) | `area:autonomy` `owner:claude` `build` | open |
| 32 | [Historique d'URL passif (gau / waymore) dans bh-recon](032-historique-d-url-passif-gau-waymore-dans-bh-recon.md) | `area:autonomy` `owner:hermes` `build` | open |

## P2

| # | Tâche | Labels | Statut |
|---|---|---|---|
| 18 | [Parallélisme dans le quota](018-parallelisme-dans-le-quota.md) | `area:autonomy` `owner:claude` `build` | open |
| 19 | [Mode CVE : analyse de variantes de patchs récents](019-mode-cve-analyse-de-variantes-de-patchs-recents.md) | `area:cve` `owner:claude` `build` | open |
| 20 | [Connecteur Intigriti (H4)](020-connecteur-intigriti-h4.md) | `area:scope` `owner:hermes` `build` | open |
| 21 | [Capture de session humaine via le gate (4.5)](021-capture-de-session-humaine-via-le-gate-4-5.md) | `area:gate` `owner:claude` `build` | closed |
| 22 | [Comparer notre PoC triager au YWH Claude Kit](022-comparer-notre-poc-triager-au-ywh-claude-kit.md) | `area:verify` `owner:claude` `research-check` | open |
| 30 | [Outils bh-sast et bh-deps (Semgrep, OSV-Scanner hors ligne)](030-outils-bh-sast-et-bh-deps-semgrep-osv-scanner-hors.md) | `area:cve` `owner:hermes` `build` | open |
| 31 | [Outil bh-oob : tests hors bande (oob_allowed)](031-outil-bh-oob-tests-hors-bande-oob-allowed.md) | `area:gate` `owner:claude` `build` | open |
