# 11 — Autonomie sans humain pendant la chasse

Audit du 2026-11-25. Arbre de travail de la branche `tracking/issues`, avec les modifications non commitées
d'autres agents. Les numéros de ligne valent pour cet état. Ils peuvent glisser après les merges.
Suite de tests au moment de l'audit : `uv run pytest -q` → 190 passés.

Documents liés, non couverts ici :
- `docs/research/09-vision-headless.md` : vision headless (autre agent du swarm, en cours).
- `docs/research/10-sessions-anti-bot.md` : sessions autonomes, login, anti-bot (autre agent du swarm, en cours).

## 1. Résumé

- Le système sollicite un humain à **17 points de création de todo**. Seul `submit` (`verify.py:250`) est conforme à la doctrine.
- La doctrine de l'agent lui dit **4 fois** de déposer une todo (`prompt.py:14`, `:28`, `:60-61`, `:103`). Le board lui affiche une section « waiting on human » (`db.py:325`).
- Trois arrêts faute d'humain : le superviseur meurt sur `SystemExit` (`supervisor.py:69`), un refus du modèle coûte 2 h de pause sans résolution (`supervisor.py:91`), les findings d'un segment refusé ne sont pas vérifiés (`run.py:673`).
- Remplacement : une todo devient un **fait `blocker`** typé, la piste est fermée, l'agent passe à autre chose.
- Le harnais prend le reste : hôte sous WAF bloqué par le gate, identité expirée retirée de la liste, programme parqué après des refus répétés.
- Scope : jamais d'élargissement automatique. L'actif hors scope est consigné dans un fait, sans todo.
- Restent humains : la soumission des PoC vérifiés, la relecture des `inconclusive` après le triage, et l'onboarding d'un programme (hors chasse).
- Plan : 14 tâches, une par fichier ou paire de fichiers exclusive, ordre de merge en §5.3.

## 2. Inventaire des points humains

Légende du type : `auth`, `account`, `waf`, `scope-question`, `refusal`, `other`, `verify`, `submit`, `quota` (`db.py:78`), plus `stop` (arrêt faute d'humain), `ui`, `cli`, `test`, `doc`.

### 2.1 Création de todo pendant la chasse

| # | fichier:ligne | Ce qui se passe | Type | Remplacement |
|---|---|---|---|---|
| 1 | `src/bh/runner/prompt.py:14` | Doctrine : sur un refus du gate, « si tu penses que c'est dans le scope » → `bh-note todo scope-question`. | scope-question | Supprimer. Un refus du gate est définitif. Rien à écrire : `ingest.gate_events` résume déjà les refus (`ingest.py:170-178`). |
| 2 | `src/bh/runner/prompt.py:27-28` | Écriture nécessaire sur l'objet d'un tiers → `bh-note todo other`. | other | `bh-note blocked write-needed "<quoi>"`. Piste fermée. |
| 3 | `src/bh/runner/prompt.py:60` | Login, 2ᵉ compte, captcha/WAF, fonction payante → `bh-note todo auth\|account\|waf`. | auth, account, waf | `bh-note blocked <raison> "<quoi>" [--intent I<n>]` puis autre surface. |
| 4 | `src/bh/runner/prompt.py:61` | « that todo is how the human unblocks you ». L'agent apprend qu'un humain viendra. | auth, account, waf | Phrase inverse : personne ne débloque pendant la chasse ; ne jamais attendre. |
| 5 | `src/bh/runner/prompt.py:103` | Sans identité : « ask via a todo if needed ». | account | « an auth wall is a blocker, not a question ». |
| 6 | `src/bh/classes.py:112-114` | Carte SSRF : SSRF aveugle → « record it as a lead for the human ». | other | `bh-note blocked oob-needed`. |
| 7 | `src/bh/agent/note.py:9`, `:58-61` | Sous-commande `bh-note todo <kind>` (kind libre, non validé côté sandbox). | tous | Remplacée par `bh-note blocked <raison>` avec raisons fermées. |
| 8 | `src/bh/runner/ingest.py:99-104` | Ingestion de l'op `todo` → `board.add_todo`. | tous | Op `blocked` → fait `blocker`. Op `todo` (anciens fichiers de notes) mappée vers `blocker`. |
| 9 | `src/bh/runner/ingest.py:124-133` | Événement gate `waf` → todo `waf` par hôte. | waf | Fait `blocker` (raison `waf`) une fois par hôte et par run. Le gate met l'hôte en pause (T13). |
| 10 | `src/bh/runner/ingest.py:137-146` | `identity-missing` → todo `account` « create var/state/identities/... ». | account | Fait `harness` : l'identité n'existe pas. L'agent voit la vraie liste via `BH_IDENTITIES` (`run.py:281`). |
| 11 | `src/bh/runner/ingest.py:150-159` | ≥ 3 × 401 avec identité → todo `auth` « session expired? ». | auth | Identité marquée périmée (meta board), retirée du prompt et de `BH_IDENTITIES` au segment suivant. Rafraîchissement : voir 10. |
| 12 | `src/bh/runner/ingest.py:160-169` | ≥ 3 × 401 sans aucune identité → todo `auth` « session needed ». | auth | Fait `blocker` (raison `auth`) par hôte. |
| 13 | `src/bh/assets.py:100-108` (+ docstring `:11`) | Hôte découvert hors scope → todo `scope-question` par hôte. | scope-question | Rien dans `todos`. `in_scope=0` reste (`assets.py:99`). Un fait `out-of-scope` par run liste les nouveaux hôtes. |
| 14 | `src/bh/runner/run.py:121-143` | `automation_allowed`/`scanners_allowed` inconnus → todo `scope-question` + `SystemExit`. | scope-question, stop | Reste une décision humaine (§4), mais **avant** la chasse : refus au préflight de `bh hunt`, sans todo. |
| 15 | `src/bh/runner/run.py:501-510` | Statut `refusal` → todo `refusal` « model refused during run N ». | refusal | Fait `blocker` (raison `refusal`) avec la dernière commande. Compteur de refus. Échelle de pause (T8). |
| 16 | `src/bh/verify.py:219-226` | Exception pendant la vérification → `inconclusive` + todo `verify`. | verify | Un réessai automatique au segment suivant. Après 2 erreurs : `inconclusive`, relu après triage (§4). |
| 17 | `src/bh/verify.py:258-265` | Verdict `inconclusive` → todo `verify`. | verify | Garder, mais requalifié « relecture post-triage » (§4). Ne bloque aucune chasse. |
| — | `src/bh/verify.py:250-257` | Verdict `verified` → todo `submit`. | submit | **Garder tel quel.** |
| — | `src/bh/board/db.py:78` | Type `quota` déclaré. Aucun appel ne le crée (`grep -rn '"quota"' src/bh` → seulement des statuts). | quota | Retirer du jeu de types. |

### 2.2 Arrêts et attentes faute d'humain

| # | fichier:ligne | Ce qui se passe | Type | Remplacement |
|---|---|---|---|---|
| 18 | `src/bh/runner/supervisor.py:69` + `run.py:554`, `:557`, `:116` | `run_segment` lève `SystemExit` (règles inconnues, conteneur arrêté, verrou pris). `hunt()` ne l'attrape pas : toute la chasse multi-programmes meurt. | stop | Préflight dans `hunt()` : programmes non prêts exclus avec un message. `ProgramNotReady` attrapée → programme parqué pour la chasse. Conteneur arrêté : la chasse s'arrête (infra, fail-closed, R7 : pas de redémarrage implicite). |
| 19 | `src/bh/runner/supervisor.py:91-94` | `refusal` ou `error` → 2 h de pause, puis on recommence pareil. Aucune trace de la cause. | stop, refusal | Échelle chiffrée : 1ᵉʳ refus → pause 6 h ; 2ᵉ dans la même chasse → programme parqué jusqu'à la fin ; 3 refus en 7 jours → exclu au préflight. |
| 20 | `src/bh/runner/run.py:673` | Pas de vérification si le segment finit en `refusal`. Les findings restent `new` jusqu'à un segment qui produit un nouveau finding. | stop | Vérifier dès que des findings `new` avec preuve existent, sauf statut `quota`. |
| 21 | `src/bh/board/db.py:324-326` | `frontier()` montre à l'agent « ## waiting on human » avec les todos ouvertes. | tous | Supprimer. Remplacer par « ## blocked (do not retry) » : les 10 derniers faits `blocker`. |
| 22 | `src/bh/runner/prompt.py:163` | Doctrine du juge : `inconclusive` si « needs state, timing or a human ». | verify | « needs state or timing you cannot reproduce ». Le juge ne compte pas sur un humain. |
| 23 | `src/bh/scope/model.py:75-76`, `:96` | Commentaires « None = unknown -> todo humaine », « refuses to start until a human decides ». | doc | Commentaire : « décidé à l'onboarding, jamais pendant la chasse ». Comportement inchangé. |
| 24 | `src/bh/gate/policy.py:110`, `:284-286` | Le gate ralentit globalement après 429/503/WAF. Il ne coupe jamais un hôte qui renvoie des challenges. L'humain était censé « marquer l'hôte comme bloqué » (`app.js:185`). | waf | Pause par hôte, décidée par le gate (T13). |

### 2.3 UI et CLI

| # | fichier:ligne | Ce qui se passe | Type | Remplacement |
|---|---|---|---|---|
| 25 | `src/bh/ui/static/index.html:17` | Onglet « Todo humaine ». | ui | Onglet « À soumettre ». |
| 26 | `src/bh/ui/static/app.js:62`, `:74`, `:77-78` | KPI et encart « Todo humaine (bloque l'agent) ». | ui | « À soumettre » + encart « Pistes bloquées » (lecture seule). |
| 27 | `src/bh/ui/static/app.js:182-189` | `TODO_HELP` pour `auth`, `account`, `waf`, `scope-question`, `refusal`. | ui | Garder `submit` et `verify` seulement. |
| 28 | `src/bh/ui/static/app.js:190-216` | Vue todo « À faire pour que l'agent continue » ; formulaire d'identité lié à une todo `auth/account/waf`. | ui | Vue post-triage. Formulaire d'identité déplacé dans un panneau « Identités » (onboarding), sans `todo_id`. |
| 29 | `src/bh/ui/server.py:289` | `open_todos` compte toutes les todos ouvertes. | ui | Compter `submit` et `verify`. |
| 30 | `src/bh/ui/server.py:316-318` | `/api/todos` sans filtre de type. | ui | Filtre sur les types post-triage. Nouvel endpoint `/api/blockers` (lecture seule). |
| 31 | `src/bh/ui/server.py:416-420`, `:454-455` | Clore une todo ; `_save_identity` ferme la todo liée. | ui | Garder `/api/identities` (onboarding). Retirer la fermeture de todo par `todo_id`. |
| 32 | `src/bh/cli.py:91-94` | Après import YWH : créer les comptes « (UI > Todo ...) ». | cli | Texte : comptes créés à l'onboarding, avant la chasse ; jamais pendant un run. |
| 33 | `src/bh/cli.py:190-192` | `bh status` : « open todos ». | cli | « to submit: N · inconclusive: M · blockers (24 h): K ». |
| 34 | `src/bh/cli.py:257-272`, `:518-522` | `bh todo` liste toutes les todos ; aide « human todo ». | cli | Liste post-triage. Nouvelle commande `bh blockers [program]`. |

### 2.4 Tests qui figent le comportement

| # | fichier:ligne | Ce qui est figé | Remplacement |
|---|---|---|---|
| 35 | `tests/test_runner_ingest.py:20`, `:24` | Une note `todo` compte comme todo (`(1, 1, 1)`). | La note devient un fait `blocker`. |
| 36 | `tests/test_runner_ingest.py:28-40` | 401 → todos `auth` (« ask the human », « expired »). | 401 → fait `blocker` ou identité périmée ; zéro todo. |
| 37 | `tests/test_program_rules.py:34-40` | `check_automation` crée une todo `scope-question`. | Lève `ProgramNotReady` ; zéro todo. |
| 38 | `tests/test_assets.py:54-55` | Hôte hors scope → todo « not in scope ». | `new_out_of_scope` rempli ; zéro todo. |
| 39 | `tests/test_board.py:10-11` | `add_todo("auth", ...)` accepté. | `add_todo` refuse un type hors `submit`/`verify`. |
| 40 | `tests/test_supervisor.py:20-41` | Aucune couverture de `refusal` ni de `SystemExit`. | Ajouter l'échelle de refus et le parcage. |

### 2.5 Documents qui décrivent l'ancien modèle

- `docs/architecture.md:88-96` : tableau « Todo humaine » avec `auth`, `waf`, `account`, `scope-question`, `refusal`.
- `docs/TODO.md:106` (4.4 « détection todo ») et `:107` (4.5 capture de session humaine).
- `docs/plan-v3.md:60` (`inconclusive` → todo humaine), `:79` (« tout cas douteux → todo humaine »), `:121` (capture humaine).
- `docs/issues/021-capture-de-session-humaine-via-le-gate-4-5.md` : capture par login manuel.
- `docs/TODO.md:58` annonce des tables `hints`, `refusals`, `handoffs`. Elles n'existent pas dans `db.py:21-56`. Les handoffs sont des faits `kind=handoff`. Écart doc/code, sans effet ici.

### 2.6 Décompte par type (points de création de todo)

| Type | Créateurs | Où |
|---|---|---|
| auth | 3 | `prompt.py:60`, `ingest.py:150`, `ingest.py:161` |
| account | 3 | `prompt.py:60`, `prompt.py:103`, `ingest.py:138` |
| waf | 2 | `prompt.py:60`, `ingest.py:125` |
| scope-question | 3 | `prompt.py:14`, `assets.py:102`, `run.py:135` |
| refusal | 1 | `run.py:503` |
| other | 2 | `prompt.py:28`, `classes.py:114` |
| verify | 2 | `verify.py:220`, `verify.py:259` |
| submit | 1 (gardé) | `verify.py:251` |
| quota | 0 | déclaré seulement (`db.py:78`) |

Total : 17 créateurs, 16 à remplacer. Plus 3 arrêts (#18-20), 1 affichage agent (#21), 10 points UI/CLI, 6 tests.

## 3. Remplacement autonome, type par type

Principe commun. Une todo pendant la chasse devient un **fait `blocker`**. Format du titre : `[<raison>] <quoi>`.
Raisons fermées : `auth`, `account`, `waf`, `captcha`, `paid`, `write-needed`, `oob-needed`, `refusal`, `other`.
Le fait reste visible dans le board et dans l'UI. Il ne réveille personne. La piste liée (`--intent`) est fermée.
Le kind `blocked` existe déjà pour le résumé des refus du gate (`ingest.py:176`). `frontier()` n'en garde que le dernier (`db.py:302-303`). Il faut donc un kind distinct : `blocker`.

### 3.1 `auth` — mur de login, session expirée

- (a) Harnais. 401 répétés **avec** identité : l'identité est marquée périmée (`meta identity-stale:<nom>:<prog>` = horodatage). Elle sort de `BH_IDENTITIES` et du prompt au segment suivant. La marque tombe quand le fichier d'identité est plus récent qu'elle.
- (a) Harnais. Rafraîchir une session sans humain (rejouer un login, cookie longue durée) relève de `10-sessions-anti-bot.md`. Ce document ne fixe que le contrat : l'hôte possède `var/state/identities/<prog>/*.json` ; l'agent ne voit jamais un secret.
- (c) Piste bloquée. 401 répétés **sans** identité : fait `blocker` `[auth] <hôte> exige une session`, une fois par hôte. L'agent teste ce qui est public.

### 3.2 `account` — 2ᵉ compte, rôle manquant

- (a) Harnais, à l'onboarding seulement. Les identités sont créées avant la chasse (UI « Identités » ou fichier). Si 10 propose une inscription autonome, elle passe par un champ de scope explicite (voir §6, risque R3), jamais par défaut.
- (c) Piste bloquée. Pendant la chasse, IDOR sans 2ᵉ compte : `bh-note blocked account "<ce qu'il faudrait>"`. La piste est fermée.
- Identité inconnue demandée (`identity-missing`, `addon.py:339-343`) : fait `harness`. Le gate refuse déjà de l'utiliser pour une écriture (`addon.py:343`).

### 3.3 `waf` / `captcha` — challenge anti-bot

- (a) Harnais, dans le gate (seule frontière dure). Après K = 3 réponses WAF sur un hôte en 10 min, le gate refuse cet hôte pendant 1 h avec la raison `waf-cooldown`. Le refus passe par le chemin existant (`X-BH-Gate: denied`). L'agent le traite comme un refus de scope : pas de réessai.
- (c) Piste bloquée. Fait `blocker` `[waf] <hôte>` par hôte et par run. Le graphe d'actifs marque l'origine bloquée jusqu'à l'échéance. Ses endpoints sortent de la liste « untested ».
- (b) Résoudre un challenge (navigateur headless, empreinte) relève de 09 et 10. Position de ce document : pas de résolution de captcha. Raison : contournement de contrôle, contraire aux règles usuelles des programmes (voir §6, R4).

### 3.4 `scope-question` — actif hors scope, règles du programme

- Jamais d'élargissement automatique. Le scope YAML n'est écrit que par un humain ou par `bh scope import` lancé par un humain.
- Hôte découvert hors scope : `in_scope=0` (inchangé, `assets.py:99`). Un seul fait `out-of-scope` par run liste les nouveaux hôtes. Pas de todo.
- Refus du gate : définitif pour l'agent. La doctrine ne lui offre plus de canal pour le contester.
- `automation_allowed` / `scanners_allowed` inconnus : reste humain (§4). Mais la question se pose à l'onboarding. `bh hunt` exclut le programme au préflight, avec un message, sans arrêter les autres.

### 3.5 `refusal` — le modèle refuse

Pas de reformulation automatique de l'action refusée. Raisons :
1. Reformuler pour passer un refus de sécurité ressemble à un contournement. Le compte est sous CVP Defense (mémoire projet). Un motif de refus répété est un signal de risque pour ce compte.
2. Le harnais ne sait pas quelle action a été refusée. Il ne voit qu'un `stop_reason` (`run.py:362`). Une reformulation serait aveugle.

Traitement chiffré :
- Fin de segment en `refusal` : fait `blocker` `[refusal] run <id>` avec la dernière commande de `res.tool_log` (200 caractères) et le chemin du log.
- Segment suivant : session neuve (déjà le défaut, `supervisor.py:22`). La tâche dit : « le segment précédent a fini sur un refus pendant : <commande> ; cette piste est close ; ne la reformule pas ».
- Échelle (T8) : 1ᵉʳ refus → pause 6 h ; 2ᵉ refus dans la même chasse → programme parqué jusqu'à la fin ; 3 refus en 7 jours (meta `refusals:<prog>`) → exclu au préflight jusqu'à décision humaine hors chasse.
- Les findings déjà écrits dans un segment refusé sont vérifiés quand même (#20).
- Recoupe `docs/issues/011-budget-par-piste-et-abandon-chiffre.md` : même mécanique d'abandon chiffré.

### 3.6 `other` — écriture sur un tiers, SSRF aveugle, fonction payante

- (c) Piste bloquée avec la raison précise : `write-needed`, `oob-needed`, `paid`.
- Aucun moyen de lever `write-needed` sans humain. C'est voulu : règle de sûreté des données (`prompt.py:22-29`).
- `oob-needed` pourrait être levé par un listener hors bande. Non proposé ici : nouvelle sortie réseau, hors du gate.

### 3.7 `verify` — vérification non concluante

- Erreur technique (exception, `verify.py:217`) : le finding repasse `new` avec un compteur (`meta verify-err:F<id>:<prog>`). Réessai au segment suivant. Après 2 erreurs : `inconclusive` + todo `verify`.
- Verdict `inconclusive` : todo `verify` gardée, mais lue **après** le triage, au même moment que `submit`. Justification en §4.

## 4. Ce qui reste humain

1. **Soumettre les PoC vérifiés** (todo `submit`, `verify.py:250`). C'est la doctrine. Raison de fond : la plateforme et le programme engagent le compte du chasseur (`plan-v3.md:61`, politique Bugcrowd citée).
2. **Relire les `inconclusive`** (todo `verify`). Après le triage, jamais pendant la chasse. Raison : les filtres automatiques écartent de vrais positifs (`plan-v3.md:60`, arXiv:2601.22952). Les jeter sans regard perd des findings. Les soumettre sans regard enverrait du non prouvé. Cette relecture ne bloque aucun segment. **Décision pour Mio** : si elle sort de la doctrine, les `inconclusive` restent un statut visible dans l'onglet Findings, sans todo.
3. **Onboarding d'un programme**, hors chasse : lire les règles et fixer `automation_allowed` / `scanners_allowed` (`run.py:121-143`). Raison de sécurité forte : c'est l'autorisation légale de tester. Un agent ne peut pas s'accorder lui-même cette autorisation. Une erreur de lecture vaut test non autorisé, puis bannissement. Même chose pour toute modification du scope YAML.
4. **Bouton d'arrêt** (`server.py:422-427`, Ctrl-C de `bh run`). C'est un droit d'interrompre, pas un besoin de la chasse. Il reste.

Tout le reste sort de la boucle.

## 5. Plan de modification (swarm)

Règles du plan :
- Une tâche = des fichiers en propriété exclusive. Personne d'autre ne les touche.
- `src/bh/agent/` reste stdlib et n'importe rien de l'hôte. L'hôte peut importer `bh.agent.contract` (c'est déjà le cas, `ingest.py:15`).
- Le gate reste la seule frontière dure. Le seul ajout au gate (T13) est une restriction.
- Chaque tâche finit par `uv run pytest -q` vert et `ruff check src tests` propre.

### 5.1 Tâches

**T1 — `src/bh/agent/contract.py`** (+ `tests/agent/test_contract.py`)
- Ajouter `BLOCKER_REASONS = ("auth", "account", "waf", "captcha", "paid", "write-needed", "oob-needed", "refusal", "other")`.
- Ajouter `FACT_KINDS = ("fact", "recon", "handoff", "dead-end")` (déplacé de `note.py:25`, même valeur).
- Test : les deux tuples existent ; `"blocker"` n'est pas dans `FACT_KINDS` (réservé à l'hôte).
- Acceptation : `python -c "from bh.agent.contract import BLOCKER_REASONS"` réussit ; tests verts.

**T2 — `src/bh/board/db.py`** (+ `tests/test_board.py`)
- `TODO_KINDS = {"submit", "verify"}`. `add_todo` lève `ValueError` sur un autre type (plus de repli silencieux vers `other`, `db.py:277-278`).
- Migration au démarrage, une seule fois (meta `todos-v2`) : `UPDATE todos SET status='obsolete', closed=? WHERE status='open' AND kind NOT IN ('submit','verify')`. Pas de suppression : l'historique reste.
- `MIGRATIONS += (("runs", "blockers", "INTEGER"),)`.
- `add_blocker(program, reason, title, detail="", run_id=None) -> int` : fait `kind='blocker'`, titre `[reason] title`. `reason` hors `BLOCKER_REASONS` → `other`.
- `frontier()` : supprimer « ## waiting on human » (`:311-313`, `:324-326`). Ajouter « ## blocked (do not retry) » : 10 derniers faits `blocker` du programme.
- Tests : `add_todo("auth", …)` lève ; migration ferme une todo `waf` ouverte et garde `submit` ; `frontier()` ne contient plus « waiting on human » et liste un blocker.
- Acceptation : les 3 tests passent ; `grep -n "waiting on human" src/bh` → vide.

**T3 — `src/bh/agent/note.py`** (+ nouveau `tests/agent/test_note.py`)
- Supprimer la sous-commande `todo` (`:58-61`, docstring `:9`).
- Ajouter `blocked` : `bh-note blocked <reason> "<title>" [-d detail] [--intent I<n>] [--host H]`, `reason` dans `c.BLOCKER_REASONS`. Émet `{"op": "blocked", ...}`.
- `FACT_KINDS` lu depuis `contract`.
- Tests : `bh-note blocked waf "x"` écrit une ligne `op=blocked` ; `bh-note todo auth x` sort en erreur argparse ; raison inconnue refusée.
- Acceptation : tests verts ; `grep -n "todo" src/bh/agent/note.py` → vide.

**T4 — `src/bh/classes.py`** (+ `tests/test_classes.py`)
- `:112-114` : « record it as a lead for the human » → « record `bh-note blocked oob-needed "<url and parameter>"` ».
- Acceptation : `grep -n "for the human" src/bh/classes.py` → vide ; tests verts.

**T5 — `src/bh/verify.py`** (+ `tests/test_verify.py`)
- `verify_finding`, branche `except` (`:217-228`) : incrémenter `meta verify-err:F<id>:<prog>`. Si < 2 : statut `new`, pas de todo. Sinon : `inconclusive` + todo `verify` (inchangée).
- `_verify` `:250-265` : inchangé (`submit` et `verify` gardées).
- Tests : une exception fait repasser le finding à `new` sans todo ; la 2ᵉ donne `inconclusive` + 1 todo `verify`.
- Acceptation : tests verts.

**T6 — `src/bh/assets.py`** (+ `tests/test_assets.py`)
- `host()` `:100-108` : supprimer `add_todo`. Garder `new_out_of_scope.append`.
- Docstring `:11` : « raises a scope-question todo » → « is recorded, never a target ».
- `mark_blocked(host, reason, until)` : écrit `{"blocked": reason, "until": ts}` dans `meta` de l'hôte.
- `surface()`/`render()` : un endpoint dont l'hôte est bloqué (et `until` futur) sort de `untested` ; l'origine affiche `blocked (<reason>) until HH:MM`.
- Tests : `test_assets.py:54-55` réécrit (zéro todo, `new_out_of_scope == ["evil.other.test"]`) ; hôte bloqué → ses endpoints absents de `untested`.
- Acceptation : tests verts ; `grep -n add_todo src/bh/assets.py` → vide.

**T7 — `src/bh/runner/ingest.py`** (+ `tests/test_runner_ingest.py`) — dépend de T1, T2
- `_note` : `case "blocked"` → `board.add_blocker` ; si `intent` valide (`I?\d+`), `close_intent(id, "blocked: <reason>")`. `case "todo"` (notes anciennes) → `add_blocker` avec `reason = kind` si dans `BLOCKER_REASONS`, `scope-question` → fait `kind='out-of-scope'`, sinon `other`.
- Le 3ᵉ élément du tuple de retour devient « blockers ».
- `gate_events` retourne `GateOutcome(blockers: int, waf_hosts: set[str], stale: set[str])` :
  - `waf` → `add_blocker("waf", host)` une fois par hôte dans l'appel ; hôte ajouté à `waf_hosts`.
  - `identity-missing` → fait `harness` « identity X requested but not configured ».
  - 401 ≥ `AUTH_TODO_THRESHOLD` avec identité → `meta_set(f"identity-stale:{ident}:{program}", now)` + blocker `auth` ; `stale.add(ident)`.
  - 401 sans identité, programme sans identité → blocker `auth` une fois par hôte (dédup : meta `auth-wall:<host>:<prog>`).
- Renommer `AUTH_TODO_THRESHOLD` → `AUTH_THRESHOLD`.
- Tests : réécrire `:20-24` et `:28-40` (zéro todo ; facts `blocker` ; meta `identity-stale` posée).
- Acceptation : `grep -n add_todo src/bh/runner/ingest.py` → vide ; tests verts.

**T8 — `src/bh/runner/prompt.py`** (+ nouveau `tests/test_prompt.py`)
- `:14` : « ... Do not retry it, do not look for a bypass, do not ask for it: out of scope is final. »
- `:27-28` : « If a write on someone else's object is needed to prove it, record `bh-note blocked write-needed "<what>"` and move on. »
- `:60-61` : « Blocked (login wall, missing identity, captcha/WAF challenge, paid feature, out-of-band needed): `bh-note blocked auth|account|waf|captcha|paid|oob-needed "<what>" [--intent I<n>]`, then another surface. Nobody unblocks you during the hunt: never wait for help, never end a segment because of a blocker. »
- `:103` : « Identities: none (unauthenticated testing only; an auth wall is a blocker, not a question) ».
- `:163` : « Otherwise `inconclusive` (needs state or timing you cannot reproduce). »
- `build_task(..., refused: str = "")` : si non vide, ajoute « The previous segment ended on a model refusal while running: <refused>. That lead is closed: do not retry or reformulate it. »
- Tests : `DOCTRINE` ne contient ni `todo` ni `human` ; `build_system_prompt` sans identité contient « blocker » ; `build_task(refused="x")` contient « do not retry ».
- Acceptation : `grep -n -i "todo\|human" src/bh/runner/prompt.py` → vide ; tests verts.

**T9 — `src/bh/runner/run.py`** (+ `tests/test_program_rules.py`, nouveau `tests/test_runner_autonomy.py`) — dépend de T2, T6, T7, T8
- `class ProgramNotReady(SystemExit)` (le CLI garde son comportement).
- `check_automation` `:127-143` : plus de `add_todo`. Lève `ProgramNotReady` avec la liste des champs. Renommer `HUMAN_DECISIONS` → `ONBOARDING_DECISIONS`.
- `live_identities(board, prog) -> list[str]` : `paths.identities(prog)` moins les noms dont `identity-stale` est plus récent que le mtime du fichier. Utilisée à `:254` (prompt) et `:281` (`BH_IDENTITIES`).
- `finish()` `:501-510` : refus → `add_blocker("refusal", f"run {id}", detail=<dernière commande 200 car.> + chemin du log)` ; incrémente `meta refusals:<prog>` (JSON : liste d'horodatages, 7 jours glissants). Appelle `Graph.mark_blocked(h, "waf", now+3600)` pour `outcome.waf_hosts`. Écrit un fait `out-of-scope` si `graph.new_out_of_scope`. Stocke `blockers` dans `runs`.
- `_run_locked` : `build_task(..., refused=...)` à partir du dernier fait `blocker` `[refusal]` du run précédent.
- `:673` : vérifier si `res.status != "quota"` et qu'il existe des findings `new`/`verifying` avec preuve (pas seulement `res.new_findings`).
- Tests : `test_program_rules.py:34-40` → `ProgramNotReady` levée, zéro todo ; identité périmée absente de `BH_IDENTITIES` ; `finish` sur `refusal` → 1 fait `blocker`, 0 todo, compteur à 1.
- Acceptation : `grep -n add_todo src/bh/runner/run.py` → vide ; tests verts.

**T10 — `src/bh/runner/supervisor.py`** (+ `tests/test_supervisor.py`) — dépend de T9
- Préflight avant la boucle : `check_automation` et refus récents (`refusals:<prog>` ≥ 3 en 7 jours) → programme exclu, une ligne imprimée. Aucun programme prêt → sortie propre.
- `run_segment` entouré de `try/except ProgramNotReady` → programme parqué jusqu'à la fin de la chasse. Les autres `SystemExit` (conteneur, verrou) remontent : arrêt fail-closed.
- `REFUSAL_COOLDOWN_S = 6 * 3600`. 1ᵉʳ `refusal` → pause 6 h ; 2ᵉ dans la même chasse → `parked = True`. `error` garde `COOLDOWN_S`.
- Tests : 3 programmes, `b` refuse deux fois → `b` appelé 2 fois puis plus jamais, `a` et `c` continuent ; `ProgramNotReady` sur `c` → `a` et `b` continuent.
- Acceptation : tests verts ; une chasse simulée ne lève plus sur un programme non prêt.

**T11 — `src/bh/cli.py`** (+ `tests/test_cli.py`)
- `:91-94` : « create test accounts with your @yeswehack.ninja alias and store them as identities before the hunt (UI > Identités or var/state/identities) ».
- `:190-192` : « to submit: N · inconclusive: M · blockers (24 h): K ».
- `cmd_todo` : liste `submit` et `verify`. Aide `:518` : « post-triage todo (submit, inconclusive) ».
- Nouvelle commande `bh blockers [program] [--since H]` : lecture seule des faits `blocker`.
- Tests : `blockers` dans les sous-commandes ; `bh todo` n'affiche pas une todo obsolète.
- Acceptation : tests verts.

**T12 — `src/bh/ui/server.py` + `src/bh/ui/static/index.html` + `src/bh/ui/static/app.js`** (+ `tests/test_ui.py`)
- `server.py:289` : `to_submit` (todos `submit` ouvertes), `inconclusive` (todos `verify` ouvertes).
- `server.py:316-318` : `/api/todos` filtré sur `submit`, `verify`. Nouveau `GET /api/blockers` (faits `blocker`, 100 derniers).
- `server.py:454-455` : retirer la fermeture par `todo_id`.
- `index.html:17` : onglet « À soumettre ». Nouvel onglet « Identités » (formulaire actuel, hors todo).
- `app.js:62-78`, `:182-216` : `TODO_HELP` réduit à `submit` et `verify` ; encart « Pistes bloquées » ; plus aucun texte « bloque l'agent » ni « pour que l'agent continue ».
- Tests : `/api/blockers` répond ; `/api/todos` ne renvoie pas une todo `waf`.
- Acceptation : tests verts ; `grep -n "bloque l'agent\|pour que l'agent continue" src/bh/ui` → vide.

**T13 — `src/bh/gate/policy.py` + `src/bh/gate/addon.py`** (+ `tests/test_gate_policy.py`)
- `policy.py` : `penalize(host: str | None = None, waf: bool = False)`. Fenêtre par hôte : K = 3 réponses WAF en 600 s → `host_blocked_until[host] = now + 3600`. Dans la décision cible, un hôte bloqué → `deny("waf-cooldown: <host> until HH:MM")`. Le ralentissement global reste.
- `addon.py:428-429` : passer `host` et `waf` à `penalize`. Docstring `:5` : « board facts » au lieu de « human todos ».
- Restriction pure : aucune règle n'autorise ce qui était refusé.
- Tests : 3 WAF sur `a.t` → `a.t` refusé, `b.t` autorisé ; après 3600 s simulées → `a.t` autorisé.
- Acceptation : tests verts ; suite d'évasion `tests/escape/escape_check.sh` toujours 29/29 (lancée par Mio : elle exige la stack).

**T14 — docs** : `docs/architecture.md`, `docs/TODO.md`, `docs/plan-v3.md`, `docs/issues/021-*.md`, `src/bh/scope/model.py` (commentaires `:75-76`, `:96` uniquement)
- §8 de l'architecture : tableau « Todo post-triage » (`submit`, `verify`) + tableau « Blocages pendant la chasse » (raison → traitement).
- `TODO.md:106-107`, `plan-v3.md:60`, `:79`, `:121`, issue 021 : renvoi vers ce document et vers 10.
- Acceptation : `grep -n "todo humaine" docs/architecture.md` ne renvoie que la section post-triage.

### 5.2 Fichiers non touchés

`src/bh/scope/enforce.py`, `normalize.py`, `psl.py`, `yeswehack.py`, `src/bh/agent/hooks.py`, `tools.py`, `q.py`, `proof.py`, `main.py`. Aucun ne crée ni n'attend de todo.

### 5.3 Ordre de merge

1. T1 (contrat agent).
2. T2 (board).
3. En parallèle : T3, T4, T5, T6, T8, T13.
4. T7 (ingest ; besoin de T1, T2).
5. T9 (runner ; besoin de T2, T6, T7, T8).
6. T10 (superviseur ; besoin de T9).
7. En parallèle : T11, T12.
8. T14 (docs) en dernier, pour citer les lignes finales.

Critère global : `grep -rn "add_todo" src/bh` ne renvoie que `verify.py` (`submit`, `verify`). `uv run pytest -q` vert. `ruff check src tests` propre.

## 6. Risques introduits par l'autonomie, et garde-fous

| # | Risque | Garde-fou |
|---|---|---|
| R1 | L'humain n'est plus alerté. Un blocage systémique (toutes les identités périmées, WAF partout) passe inaperçu. | Colonne `runs.blockers` ; `bh status` et l'UI affichent les blockers des 24 h. Une chasse dont tous les programmes sont parqués s'arrête avec un message. |
| R2 | Un actif légitime oublié dans le scope n'est jamais testé. | Accepté. Fail-closed. Le fait `out-of-scope` par run est relu à l'onboarding suivant. Jamais d'ajout automatique au YAML. |
| R3 | Inscription autonome de comptes (si 10 la propose). Limite de comptes, adresse imposée (`@yeswehack.ninja`), interdiction selon les programmes. | Champ de scope à ajouter avec 10 (ex. `self_signup: true/false/null`). `null` = interdit, comme `scanners_allowed` (`model.py:96`). Fixé à l'onboarding seulement. |
| R4 | Résolution de captcha ou contournement WAF. Contournement de contrôle, contraire à la plupart des règles de programmes. | Pas de résolution. Pause par hôte dans le gate (T13). Toute autre option doit passer par 10 avec une règle de programme citée. |
| R5 | Refus du modèle reformulés en boucle. Ressemble à un contournement des garde-fous ; risque pour le compte CVP. | Zéro reformulation. Échelle 6 h → parcage → exclusion. Piste close explicitement dans la tâche suivante. |
| R6 | Le texte des cibles pousse l'agent à écrire des blockers. | Impact borné : un blocker est un fait, il ne déclenche aucune action. Gain net : l'ancienne todo portait du texte de cible jusqu'à l'humain (ingénierie sociale de l'opérateur). |
| R7 | Identité marquée périmée à tort (401 normal sur un endpoint admin). | Seuil inchangé (3 × 401 par hôte et identité). La marque tombe dès que le fichier d'identité est réécrit. L'agent garde les autres identités. |
| R8 | Un programme parqué cache un problème du harnais (pas un refus réel). | Le fait `blocker` `[refusal]` contient la dernière commande et le chemin du log. `error` n'est pas compté comme un refus. |
| R9 | Le gate refuse un hôte en `waf-cooldown` pendant la vérification d'un finding. | Le juge reçoit le refus gate comme n'importe quel refus : `inconclusive`, réessai au segment suivant (T5). Aucun contournement. |
| R10 | Données de tiers. L'autonomie ne change pas les règles d'écriture. | Inchangé : écriture seulement avec `X-BH-Identity` (`policy.py:188-189`), `write-needed` clôt la piste. |

Point non tranché dans le code : `verify_pending` ne s'exécute qu'après un segment avec de nouveaux findings (`run.py:673`). Seul autre déclencheur : `bh verify` (`cli.py:214`, `:234`). T9 corrige ce point. Il faut le confirmer en lab : un finding laissé `new` est vérifié au segment suivant.

## Décision de Mio (2026-11-25) : `inconclusive` → second juge Mythos

Un finding que le juge Opus laisse `inconclusive` n'ouvre plus de todo. Le harnais relance l'étage B une fois,
avec un second juge `claude-mythos-5-2` (effort `high`), contexte neuf, même rejeu et même nonce.
- Mythos tranche `verified` ou `rejected` : le statut est appliqué. Seul `verified` crée la todo `submit`.
- Mythos reste `inconclusive` : statut final visible dans l'onglet Findings, sans todo.
- Une seule escalade par finding (champ en base), modèle réglable par `BH_ESCALATION_MODEL`.
- Le relais du gate ne filtre pas le modèle (`src/bh/gate/addon.py:72`, journalisé seulement) : Mythos y passe.
  Mythos a l'accès CVP sur le compte de Mio (audit du 2026-11-24) ; Fable ne l'a pas.
