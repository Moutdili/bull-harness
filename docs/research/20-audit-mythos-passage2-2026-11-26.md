# Audit bull-harness, passage 2 (Mythos, 2026-11-26)

Lecture seule, rien exécuté, aucun test lancé. **P** = lu dans le code cité. **S** = supposé, avec la mesure qui tranche. Les `fichier:ligne` sont ceux de la copie lue pendant ce passage. « Test » veut dire : le test existe et vérifie ce point, pas qu'il passe.

## 1. Verdict

- **Pas encore.** Le code des bloquants est là pour l'essentiel (22 items corrigés sur 37), mais quatre points empêchent de lancer Sonnet tel quel.
- **Anti-bot non prouvé sur la vraie page** (B4, N2) : la détection échoue ouverte sur une page longue sans frame Turnstile attachée, et la fixture est reconstruite. Un snapshot réel doit dire `pending: true` avant toute chasse.
- **Reprise après challenge cassée par construction** (N3) : `wait-human` dit « cleared » pendant que l'écran `/captcha/` de Mio verrouille encore toutes les actions (409 `human-viewing`, même code de sortie 3).
- **Rien n'est épinglé** (I7) : `scopes/msrc/copilot.yaml` n'a pas de clé `cards:`, sa note demande encore « MSOBB » et `bh-note blocked captcha`. Les 9 cartes de `out/cards/` et `out/cards.yaml` ferment ce point une fois copiées.
- **Deux mesures restent des portes d'entrée** : rotation effective des jetons (B1), et deux identités HTTP qui marchent sur une API authentifiée (B6). Si cette API est sur substrate, N1 la bloque (aucun bearer capturé pour une cible déclarée par préfixe d'URL).

## 2. Tableau de vérification (37 items)

Compte : corrigé 22, partiel 10, non corrigé 1, régression 1, non vérifiable par lecture 3, non vérifié (budget) 0.

| ID | Verdict | Preuve `fichier:ligne` | Test | Ce qui manque |
|---|---|---|---|---|
| B1 | non vérifiable par lecture | `src/bh/cli.py:250-260, 522-525, 884-885` ; `src/bh/ui/server.py:94-116` ; `src/bh/browser_service/notify.py:66-71` | `tests/test_ui_captcha.py::test_rotation_reaches_the_running_ui_and_kills_old_sessions` ; `tests/test_browser_watch.py::test_notify_rotate_replaces_the_topic` | Les commandes existent (P). La rotation elle-même : `secrets/` absent. Mesure : ancien cookie UI → 401, un POST sur l'ancien topic n'arrive plus au téléphone. |
| B2 | corrigé | `src/bh/gate/policy.py:253-254, 293-294, 304-305` ; `src/bh/gate/addon.py:253-266, 544-546, 776` ; `scopes/msrc/copilot.yaml:33-35` ; `src/bh/runner/prompt.py:317-320` | `tests/test_gate_browser_canary.py::test_a_websocket_handshake_is_the_browsers_alone`, `::test_a_browser_only_path_is_refused_to_everyone_but_the_browser` ; `tests/test_gate_sso_passthrough.py::test_passthrough_connect_from_the_agent_is_browser_only` | S : un chemin HTTP porteur de prompt hors `/m365Copilot/Chathub/` n'est tenu que par la doctrine. Mesure : routes de `/m365Copilot/` et de `copilot.com` vues dans `flows.jsonl`. |
| B3 | corrigé | `src/bh/browser_service/controller.py:424-434, 638-646, 666` ; `src/bh/browser_service/watch.py:63-76` | `tests/test_browser_controller.py::test_the_marker_survives_a_restart_and_blocks_another_identity` ; `tests/test_browser_watch.py::test_prepare_resets_a_profile_holding_another_identity_before_adding_cookies` | Live : `bh browser status` nomme la bonne identité après redémarrage du conteneur. Voir N19 (effacement sans contrôle). |
| B4 | partiel | `src/bh/browser_service/detect.py:23-27, 52-64` ; `src/bh/browser_service/controller.py:1010-1016` | `tests/test_browser_controller.py::test_the_copilot_verification_required_dom_is_a_pending_challenge`, `::test_unknown_visibility_of_a_challenge_frame_fails_closed` | Fixture reconstruite (`docs/research/18-…:167-168`). Page longue, libellé présent, pas de frame Turnstile : non détecté (`tests/test_browser_controller.py:94`). Voir N2. |
| B5 | corrigé | `scopes/msrc/copilot.yaml:26-30` ; `src/bh/scope/enforce.py:93-109` | `tests/test_gate_support_ws.py::test_copilot_scope_targets_and_support` | Rien pour le périmètre. Effet de bord : N1 (plus de bearer capturable pour substrate). |
| B6 | partiel | `scopes/msrc/copilot.yaml:65, 103` ; `src/bh/accounts/enroll.py:229-249` ; `src/bh/gate/addon.py:774-780` ; `src/bh/runner/prompt.py:193-212` | `tests/test_gate_browser_canary.py::test_the_probe_from_the_gates_loopback_borrows_the_identity` ; `tests/test_prompt.py::test_identities_without_a_probe_are_said_unchecked` | Sonde = statut seul de `copilot.com/chat`, sans `expect` propre au compte, rien sur substrate. Mesure : `qq <API authentifiée>` rend user-a 200, user-b 200, anonyme 401, à T0 et T0+90 min. |
| B7 | partiel | `src/bh/cards/prompt-injection.md:5-6` ; `src/bh/runner/prompt.py:124-125, 144-150, 171-190` ; `src/bh/agent/contract.py:90-91` ; `src/bh/board/db.py:392-397, 413-414` | `tests/test_audit_s3.py::test_frontier_challenge_blocker_lives_30_minutes_under_retry` ; `tests/test_classes.py::test_prompt_injection_card_loads_with_its_cross_user_standard` | Les quatre points sont dans le code. Mais quatre textes lus par le chasseur disent encore `bh-note blocked captcha` après une attente (N5). |
| B8 | non vérifiable par lecture | `src/bh/gate/policy.py:568, 584` ; `src/bh/gate/addon.py:781-782` ; `src/bh/gate/policy.py:320, 396` ; `src/bh/cli.py:859-860` | aucun (mesures live) | Cinq mesures, critères en §5. Le code relève la durée ws de bh-browser à 3600 s et lui ouvre PUT/PATCH/DELETE ; `--minutes` vaut toujours 30 par défaut. |
| I1 | corrigé | `src/bh/agent/note.py:53-62, 82-105` ; `src/bh/runner/observation.py:64-95, 128-142` ; `src/bh/gate/addon.py:493-524` ; `src/bh/verify.py:470-538` ; `src/bh/runner/ingest.py:139-155` | `tests/test_audit_s3.py::test_canary_seen_on_both_sides_is_verified_evidence`, `::test_canary_typed_by_the_attacker_is_rejected`, `::test_judge_can_only_lower_the_hosts_verdict` | Bout en bout jamais mesuré en live. Limites : N6 (auto-exfiltration acceptée), N7 (canari invisible dans un chemin HTTPS). |
| I2 | corrigé | `src/bh/browser_service/__init__.py:39-42` ; `src/bh/browser_service/controller.py:623-629` ; `src/bh/browser_service/watch.py:180-207` ; `src/bh/browser_service/host.py:138-166` ; `src/bh/gate/addon.py:472-491, 781-782, 833-834` | `tests/test_gate_browser_canary.py::test_browser_traffic_carries_the_identity_the_host_loaded`, `::test_identity_only_methods_for_the_browser_under_its_identity_not_for_the_agent` ; `tests/test_browser_watch.py::test_a_switch_to_a_live_identity_is_carried_out` | Variante minimale seulement (un challenge par bascule). `switch` jamais mesuré ; le prompt ne le nomme pas (N4) ; un échec laisse le profil vide (N13). |
| I3 | corrigé | `src/bh/browser_service/controller.py:561-608, 924-929` ; `src/bh/agent/hooks.py:28-30, 109-118, 147` | `tests/test_browser_controller.py::test_text_tail_gives_the_end_of_a_long_chat`, `::test_outline_attr_tabs`, `::test_upload_is_in_memory_and_bounded` ; `tests/agent/test_hooks.py::test_bh_web_text_and_frames_are_shown_whole` | `upload` jamais mesuré sur le composeur. `outline` reste tronqué par le hook, l'exemption tombe dès qu'un sélecteur contient `(` ou `>` (N21). |
| I4 | corrigé | `src/bh/browser_service/controller.py:909-919, 610-621` ; `src/bh/browser_service/detect.py:93-132` | `tests/test_browser_controller.py::test_no_frame_output_carries_a_challenge_token` | Live : `bh-web frames` sur le hub SignalR (S : un websocket ouvert dans un worker n'est pas vu par `page.on("websocket")`). |
| I5 | corrigé | `src/bh/agent/contract.py:613-648` | `tests/test_audit_s3.py::test_url_in_bh_web_text_or_selector_is_neither_locked_nor_tested` | Rien. |
| I6 | corrigé | `src/bh/gate/policy.py:83, 259, 306, 320, 396, 418-424` ; `src/bh/gate/addon.py:994, 998` | `tests/test_gate_policy.py::test_id_enumeration_counts_path_ids_only` ; `tests/test_gate_browser_canary.py::test_the_browser_is_never_paused_by_the_waf_guard` | Live : huit « New chat » en 10 min sans refus. La doctrine annonce encore 4 identifiants (N11). Les 429/503 du navigateur ne ralentissent plus rien (N20). |
| I7 | partiel | `src/bh/scope/model.py:132, 192, 415-417` ; `src/bh/classes.py:351-384` ; `src/bh/runner/run.py:1444, 1502-1512` ; `container/compose.yaml:105` | `tests/test_audit_s3.py::test_pinned_card_is_in_the_first_task`, `::test_pinned_cards_from_a_real_loaded_scope`, `::test_cards_mounted_read_only_for_the_agent` | Le mécanisme existe. `scopes/msrc/copilot.yaml` n'a pas de clé `cards:` et aucune fiche Copilot n'est dans `src/bh/cards/` : livrées dans `out/`, à copier. |
| I8 | partiel | `src/bh/runner/prompt.py:63-74, 89-92, 106-115, 160-164` | `tests/test_audit_s3.py::test_no_scanner_name_in_the_prompt_of_a_scope_without_scanners` | La doctrine est propre. Les cartes de classe choisies nomment encore des scanners (`src/bh/classes.py:25`, `src/bh/cards/xss.md:4`, `sqli.md:4`, `broken-access-control.md:11`, `info-disclosure.md:2`) ; le test ne couvre pas les cartes (N18). |
| I9 | corrigé | `src/bh/runner/run.py:73-76, 87-93, 1313-1328, 1404-1408` | `tests/test_audit_s3.py::test_segment_limits_for_a_browser_scope`, `::test_handoff_carries_the_browser_state_and_never_fails` | Live : un segment de 100 tours utilise son budget (60 k, 5 legs). |
| I10 | corrigé | `src/bh/gate/policy.py:755-758` ; `src/bh/verify.py:50, 62-70` ; `src/bh/runner/run.py:1697` | `tests/test_audit_s3.py::test_judge_model_is_never_the_hunters` | Live avant l'étape 3 : un `count_tokens` puis un message `claude-mythos-5-2` passent depuis l'agent. |
| I11 | corrigé | `src/bh/agent/contract.py:80-86` ; `src/bh/runner/run.py:196-226, 518-609, 1537, 1687-1688` ; `src/bh/runner/prompt.py:43-45` | `tests/test_audit_s3.py::test_stop_note_pushes_stops_and_parks_within_30_seconds`, `::test_stop_reasons_are_blocker_reasons` | Les skills et le doc 15 donnent encore le geste `bh-note blocked other`, qui ne déclenche pas l'arrêt (N10). |
| I12 | corrigé | `src/bh/browser_service/watch.py:22-23, 155-178` ; `src/bh/browser_service/notify.py:23-26, 87-92` ; `src/bh/agent/web.py:39-41` ; `src/bh/browser_service/controller.py:376-378, 530-535` ; `src/bh/ui/server.py:351-380, 411-415` | `tests/test_browser_watch.py::test_a_challenge_is_pushed_once_then_reminded_once_at_ten_minutes` ; `tests/agent/test_web.py::test_wait_human_ends_before_the_bash_tool_timeout` ; `tests/test_ui_captcha.py::test_an_open_screen_tells_human_viewing_on_then_off_when_the_last_one_closes` | Les quatre correctifs sont là. Le verrou `human_viewing` crée N3 : `wait-human` ne l'attend pas. |
| I13 | régression | `src/bh/gate/policy.py:373-376` ; `src/bh/scope/model.py:98-103` ; `scopes/msrc/copilot.yaml:40-41` | `tests/test_gate_sso_passthrough.py::test_sso_get_only_under_get_paths_for_the_hunter` ; `tests/escape/escape_check.sh:92` | Le défaut est fermé, mais sans `get_paths` dans le scope tout GET `sso` de l'agent est refusé : `bh-browse --as` perd la connexion silencieuse que la tâche R4 et le juge utilisent (N9). Phrase de doctrine absente. |
| I14 | corrigé | `src/bh/agent/contract.py:585-596` ; `src/bh/agent/hooks.py:49-50` ; `src/bh/agent/browse.py:169-172` ; `src/bh/runner/prompt.py:69-70` | `tests/test_audit_s3.py::test_single_page_xss_passes_without_scanners_a_multi_page_variant_does_not` | Docstring périmée (`src/bh/agent/browse.py:25` dit encore « with --xss a scanner »). |
| I15 | partiel | `tests/escape/escape_check.sh:90-99, 102-125` | `tests/escape/escape_check.sh` (profils `msrc` et `host`) | Manquent : SNI différent du CONNECT, `goto` loopback. Les tests du gate restent sur de faux flux (`tests/test_gate_browser_canary.py:124-146`, `SimpleNamespace`). |
| I16 | partiel | `src/bh/cli.py:384-403, 873` ; `.claude/skills/msrc-ai-bug-bounty/SKILL.md:189-191` ; `.claude/skills/ai-red-team-pyrit/SKILL.md:122-133` | `tests/test_audit_s3.py::test_finding_and_board_fence_the_hunters_text`, `::test_quiet_run_prints_counts_only` | Aucun `CLAUDE.md` dans la copie : la règle de l'orchestrateur n'est pas vérifiable. Skills à moitié mises à jour (N10). |
| I17 | corrigé | `src/bh/browser_service/controller.py:85-86, 473-491, 537-542` ; `src/bh/browser_service/watch.py:80` | `tests/test_browser_controller.py::test_the_81st_fill_of_a_segment_is_refused_and_the_host_resets_it`, `::test_the_daily_budget_is_per_identity_and_survives_a_reset_and_a_restart` | Un message envoyé sans `fill` (clic sur une suggestion, `upload` puis Entrée) n'est pas compté (N15). |
| I18 | non vérifiable par lecture | `src/bh/gate/addon.py:280-292, 643-661, 1088-1108, 1133-1139` ; `src/bh/gate/policy.py:584` | `tests/test_gate_browser_canary.py::test_close_connection_cancels_the_client_reader_task`, `::test_a_websocket_that_cannot_be_closed_says_so` (faux objets) | Dépend d'internes de mitmproxy 12.3.1 absents de la copie. Mesure : navigateur inactif 15 min, puis un challenge ; l'événement `blocked` porte `closed: true` et l'appli se reconnecte. |
| I19 | partiel | `src/bh/gate/session.py:54-55, 111-135` ; `src/bh/gate/addon.py:885-890` ; `src/bh/accounts/enroll.py:425-442` ; `src/bh/agent/browse.py:520-594` | `tests/test_gate_browser_canary.py::test_origin_headers_go_to_their_exact_origin_only_and_are_never_journaled` | HAR et état caviardés (P). La capture par origine ne marche pas pour une cible déclarée par préfixe d'URL : `enroll.py:436` juge l'origine nue, que `enforce.py:109` refuse (N1). |
| M1 | corrigé | `src/bh/browser_service/__init__.py:16` ; `src/bh/gate/addon.py:40-45` ; `docs/architecture.md:111-154` ; `docs/TODO.md:45-48` | aucun | Les quatre textes cités sont à jour. D'autres sont périmés (N5, N10, N12). |
| M2 | corrigé | `src/bh/gate/addon.py:306-309, 1072, 1076` | aucun | Rien. |
| M3 | non corrigé | `scopes/msrc/copilot.yaml:136` | aucun | La note renvoie toujours le chasseur à `.claude/skills/msrc-ai-bug-bounty`, qu'il ne peut pas lire. |
| M4 | partiel | `src/bh/runner/prompt.py:230, 233, 365` | `tests/test_audit_s3.py::test_verifier_doctrine_r9_and_no_bh_web_line` | La ligne `bh-web` a disparu du prompt du juge. Toutes les identités déclarées y restent listées, avec « sessions checked » (`prompt.py:233`). |
| M5 | corrigé | `src/bh/agent/tools.py:526-528` | `tests/test_audit_s3.py::test_katana_never_follows_a_sign_out_link` | Rien. |
| M6 | corrigé | `src/bh/gate/addon.py:1093-1095` | `tests/test_gate_browser_canary.py::test_a_zombie_websocket_gets_one_blocked_event_and_a_real_close` | Rien. |
| M7 | corrigé | `src/bh/browser_service/controller.py:440-445` | `tests/test_browser_controller.py::test_a_cookie_set_after_the_load_is_scrubbed_too` | Rien. |
| M8 | partiel | `src/bh/runner/prompt.py:108, 266-270` | `tests/test_audit_s3.py::test_no_scanner_name_in_the_prompt_of_a_scope_without_scanners` | La première tâche saute `bh-recon`, la Méthode dit encore « bh-recon, then bh-crawl ». La fiche C0 (`out/cards/msrc-copilot.md`) le dit, une fois épinglée. |
| M9 | corrigé | `src/bh/browser_service/controller.py:737-740` ; `src/bh/cli.py:805` | `tests/test_browser_controller.py::test_x11vnc_exchanges_no_clipboard` | Rien. |
| M10 | corrigé | `scopes/msrc/copilot.yaml:21-30` | aucun | `copilot.ai` est resté hors du scope, comme demandé. À dire dans chaque rapport MSRC (redirection vers `copilot.com`). |

## 3. Affirmations du contexte (`AUDIT-CONTEXT-PASS2.md`)

| Affirmation | Constat | `fichier:ligne` |
|---|---|---|
| Tout B1–B8, I1–I19 et les mineurs ont été traités | **P** faux en l'état : 22 corrigés, 10 partiels, 1 non corrigé, 1 régression, 3 non vérifiables | tableau §2 |
| B5 : substrate limité aux chemins Copilot | **P** vrai | `scopes/msrc/copilot.yaml:26-30` ; `src/bh/scope/enforce.py:93-109` |
| Sondes (B6) | **P** déclarées et exécutées, statut seul | `scopes/msrc/copilot.yaml:65, 103` ; `src/bh/accounts/enroll.py:229-249` |
| `browser_only` du Chathub | **P** vrai, tenu au gate quelle que soit la méthode | `scopes/msrc/copilot.yaml:33-35` ; `src/bh/gate/policy.py:304-305` |
| Identité du canari au CONNECT du navigateur | **P** vrai (nom d'hôte seulement, N7) | `src/bh/gate/addon.py:506-509, 543` |
| Décision : pas de « MSOBB » | **P** non appliquée au scope : la note le demande encore | `scopes/msrc/copilot.yaml:136` |
| Décision : reprise exacte après challenge | **P** écrite (doctrine, `wait-human`, leg suivant), mais N3 la casse tant que l'écran est ouvert | `src/bh/runner/prompt.py:180-186` ; `src/bh/agent/web.py:43-46` ; `src/bh/runner/run.py:1336-1343, 1655-1656` |
| Décision : `bh-browse <url> --xss <marqueur>` permis | **P** vrai, une page, un marqueur, sans `$`, boucle ni `--routes` | `src/bh/agent/contract.py:585-596` |
| Décision : mémoire activée sur user-b avant Opus | non vérifiable (réglage du compte) ; C6 commence par le vérifier | — |
| 80 `fill` par segment, 200 par jour et par identité | **P** vrai ; « segment » = un `bh run`, tous legs confondus | `src/bh/browser_service/controller.py:85-86` ; `src/bh/browser_service/watch.py:80` ; `src/bh/runner/run.py:1499` |
| Juge différent du modèle chasseur | **P** vrai (Opus, ou Mythos si le chasseur est Opus) | `src/bh/verify.py:50, 62-70` |
| Arrêt et ntfy sur donnée d'un tiers ou exécution serveur | **P** vrai, sans contenu, programme parqué | `src/bh/runner/run.py:518-609` |
| Les sous-agents passent par `claude -p` | non vérifiable (hors dépôt) | — |
| 918 tests verts, ruff propre | non vérifiable (pas de Bash). **P** : les tests cités en §2 existent | — |
| Évasion `msrc` : 6/6 côté agent, 3/3 côté journal | **P** le profil a bien 6 contrôles agent et 3 contrôles hôte ; résultat non vérifiable | `tests/escape/escape_check.sh:91-96, 120-122` |
| Sondes 200 après le correctif `X-BH-Probe` | **P** pour le code (le marqueur n'est honoré que depuis la boucle locale du gate et ne sort jamais) ; résultat live non vérifiable | `src/bh/gate/addon.py:774-780` ; `src/bh/accounts/enroll.py:238-240` |
| La sonde ne vérifie que le statut | **P** vrai : pas de `expect`, donc pas de preuve de quel compte répond | `scopes/msrc/copilot.yaml:64-65, 102-103` |
| `bh-web state` rend `fills`, `human_viewing`, `cleared_at` | **P** vrai | `src/bh/browser_service/controller.py:509-520` |
| « Pas encore mesuré » : ws > 10 min, reprise, `switch`, `frames`, `upload`, `navigator.webdriver`, canari bout en bout, fixture B4 | **P** cohérent avec le code ; j'y ajoute N1, N2, N3 et la mesure B6 | §5 |

## 4. Nouveaux défauts

| N | Gravité | P/S | `fichier:ligne` | Problème | Correctif | Test |
|---|---|---|---|---|---|---|
| N1 | haute | P | `src/bh/accounts/enroll.py:436` ; `src/bh/scope/enforce.py:109` ; `src/bh/scope/model.py:601-610` | `origin_headers` n'est jamais capturé pour une cible déclarée par préfixe d'URL : `_is_target("https://substrate.office.com:443")` est faux (chemin `/` hors préfixes), et déclarer substrate dans `authorization_origins` lève `ScopeError`. `q -a` vers substrate part sans bearer : pas de test HTTP entre comptes sur substrate. | Juger l'hôte quand une règle URL de même schéma et port le couvre, dans `_is_target` et `_identity_urls_in_scope`. Le gate continue de refuser les chemins hors préfixe. | Unitaire : scope à règle URL et `authorizations` de cette origine → `origin_headers` rempli. Live : `q -a user-a` sur une route GET de `/m365Copilot/` vue dans `bh-web net` ne rend pas 401. |
| N2 | haute | S | `src/bh/browser_service/detect.py:57-64` ; `tests/test_browser_controller.py:94` | Échec ouvert : page de plus de 600 caractères, libellé « Verification required », aucune frame `challenges.cloudflare.com` attachée, pas de titre d'interstitiel → `pending: false`. `click`, `fill`, `press` (Tab puis Espace compris), `goto`, `upload` passent alors sur une page en challenge. Le vrai DOM n'a jamais été capturé. | Tant qu'un vrai snapshot ne prouve pas la présence de la frame : le libellé trouvé dans la queue du texte suffit quand le scope a un hôte passthrough. | `host.save_snapshot()` pendant un vrai challenge : `challenge.pending == true`. Cas « page longue, libellé en queue, sans frame » → `pending`. |
| N3 | haute | P | `src/bh/agent/web.py:192-204` ; `src/bh/ui/static/captcha.js:19-22` ; `src/bh/browser_service/controller.py:376-378` | `wait-human` ignore `human_viewing`. Au moment où le challenge tombe, l'écran de Mio est ouvert par construction et se reconnecte seul toutes les 3 s : `press`, `click`, `fill`, `wait` rendent 409 `human-viewing` avec le code 3, celui du challenge. La doctrine dit alors « `wait-human` once », qui répond « cleared » : boucle. | `wait_human` attend aussi `human_viewing == false` ; code de sortie distinct ; `captcha.js` ferme l'écran après « J'ai fini » ; une phrase dans `BROWSER_BLOCK`. | `tests/agent/test_web.py` : `pending false, human_viewing true` ne rend pas « cleared ». |
| N4 | moyenne | P | `src/bh/runner/prompt.py:172-175` | `BROWSER_BLOCK` nomme 8 sous-commandes sur 15. `outline`, `attr`, `net`, `frames`, `tabs`, `upload`, `switch` n'existent pour le chasseur que par la carte C1. Sans `switch`, pas de victime B. | Lister les 15, ou renvoyer à la carte épinglée `bh-web-manual`. | Chaque op de `AGENT_OPS` figure dans `BROWSER_BLOCK`. |
| N5 | moyenne | P | `src/bh/agent/web.py:207-209` ; `src/bh/browser_service/controller.py:113-116` ; `scopes/msrc/copilot.yaml:136` ; `src/bh/agent/browse.py:396` | Quatre textes lus par le chasseur disent `bh-note blocked captcha` après une attente expirée, contre `BROWSER_BLOCK` (`prompt.py:184-186` : une intention, pas un blocker). | Aligner les quatre sur `BROWSER_BLOCK`. | Aucun de ces textes ne contient `blocked captcha` pour un scope à passthrough. |
| N6 | moyenne | P | `src/bh/runner/observation.py:72-79` ; `src/bh/runner/prompt.py:402-420` | `decide` rend `verified-evidence` dès que le navigateur de la victime envoie le canari vers un hôte hors scope, même si c'est le prompt de la victime qui l'a demandé (aucune charge de A). Un lien de partage voulu par B, lu par A, donne aussi « received by A ». Le juge ne reçoit ni les prompts ni le contrôle. | Champ « contrôle sans charge : 0/N » exigé avec `--observation` et montré au juge ; phrase dans `VERIFIER_DOCTRINE` : sans causalité par le contenu de A, `rejected`. | Observation sans contrôle → `inconclusive`. |
| N7 | moyenne | P | `src/bh/gate/addon.py:543, 550-552` ; `src/bh/runner/prompt.py:147-148` | Au CONNECT, seul le nom d'hôte est cherché. Un canari dans le chemin ou la requête d'une URL `https://` vers un hôte hors scope n'est jamais journalisé (CONNECT refusé avant toute requête). La doctrine ne le dit pas : un vrai finding finit `inconclusive`. | L'écrire dans la doctrine : le canari est une étiquette DNS du nom d'hôte. Les cartes C4, C5 et C7 le disent. | Canari dans le chemin d'un CONNECT refusé → aucun événement (documenté). |
| N8 | moyenne | P | `src/bh/browser_service/controller.py:591-593, 1005-1006` | `tabs --select` n'est pas gardé et la détection ne lit que l'onglet piloté : changer d'onglet pendant un challenge rend `pending: false`, pose `cleared_at`, fait dire « cleared » à `wait-human` et coupe les rappels. | `_guard()` quand `select` est donné ; challenge si un onglet quelconque en montre un. | Challenge sur l'onglet 0, `tabs --select 1` → 409. |
| N9 | moyenne | P (refus), S (effet sur l'appli) | `scopes/msrc/copilot.yaml:40-41` ; `src/bh/gate/policy.py:373-376` ; `src/bh/runner/prompt.py:266-269, 308` | Régression de I13. Le navigateur propre de l'agent (`bh-browse --as`) ne peut plus faire `GET …/authorize` ni `/savedusers` : l'appli y tourne sans jeton, alors que la première tâche lui demande d'y lister les appels d'API et que le juge y rejoue les XSS. | Recommandé pour Sonnet : garder le refus et écrire `bh-web net --last 200` à la place de `bh-browse` dans la tâche R4. Sinon déclarer `get_paths` (formes de `tests/test_gate_sso_passthrough.py:39`). | Live : `bh-browse https://copilot.com/chat --as user-a`, compter les refus `get_paths` dans `events.jsonl`. |
| N10 | moyenne | P | `.claude/skills/msrc-ai-bug-bounty/SKILL.md:14, 155` ; `.claude/skills/ai-red-team-pyrit/SKILL.md:14, 100-103` ; `.claude/skills/msrc-copilot-studio-research/SKILL.md:18, 184-190` ; `docs/research/15-msrc-premier-programme.md:41-42, 50, 57` | Skills et doc 15 périmés : canari `BH-CANARY-<id>` (le gate ne cherche que `BH-SECRET-<16 hex>`, `src/bh/gate/canary.py:24`), geste d'arrêt `bh-note blocked other` (le `StopWatcher` ne réagit qu'à `third-party-data` et `server-exec`, `src/bh/runner/run.py:570`), « s'il a un chemin HTTP, le préférer ». Un `--task` écrit d'après ces textes désarme l'arrêt. | Mettre à jour les trois skills et le doc 15. | Aucun (texte). |
| N23 | moyenne | P (code), S (libellé exact de l'échec Chromium) | `src/bh/browser_service/controller.py:581, 904-907` ; `src/bh/gate/addon.py:550-552` | `bh-web net --denied` ne montre pas un hôte `https://` hors scope : le gate refuse le CONNECT, la page ne reçoit aucune réponse, la ligne n'a que `failure` et pas `denied`. C'est le cas de l'exfiltration par URL : le chasseur lit « rien n'est parti ». | Avec `--denied`, garder aussi les lignes `failure` d'un tunnel refusé, ou marquer `denied` quand l'hôte est hors scope. Les cartes utilisent `bh-web net --last N`. | `tests/test_browser_controller.py` : une requête échouée vers un hôte hors scope apparaît avec `--denied`. |
| N11 | basse | P | `src/bh/runner/prompt.py:26` ; `src/bh/gate/policy.py:83` | La doctrine dit « more than 4 distinct object ids », le gate en admet 12. Les cartes suivent la doctrine (4). | Générer le nombre depuis `policy.ID_LIMIT`. | `tests/test_prompt.py`. |
| N12 | basse | P | `scopes/msrc/copilot.yaml:136` | La note demande « MSOBB » (décision de Mio : non) et renvoie à `.claude/skills` (M3). Le chasseur la lit à chaque tour. | Réécrire la note (texte proposé en §6). | Aucun. |
| N13 | basse | P | `src/bh/browser_service/watch.py:196-206` | Un `switch` dont le `load` échoue après le `reset` laisse le profil vide : le chasseur reste déconnecté jusqu'au segment suivant. | Recharger l'identité précédente en cas d'échec. | `tests/test_browser_watch.py`. |
| N14 | basse | P | `src/bh/gate/addon.py:955-961` ; `src/bh/gate/session.py:305-310` | Les `Set-Cookie` de bh-browser vont dans la jarre de l'identité, suppressions comprises : un « Sign out » cliqué dans `bh-web` tue aussi `q -a`. | Ne replier que les ajouts pour bh-browser. Les cartes interdisent le clic. | Unitaire sur `_identity_cookies`. |
| N15 | basse | P | `src/bh/browser_service/controller.py:537-542, 604-608` | Le budget compte les `fill`, pas les envois : un clic sur une suggestion ou un `upload` suivi d'Entrée part hors budget. `upload` n'a pas de plafond en nombre. | Plafonner `upload` par segment ; compter l'Entrée qui suit un `upload`. | `tests/test_browser_controller.py`. |
| N16 | basse | P | `src/bh/agent/web.py:149-169` | R10 à moitié : la sortie de `bh-web text`, `outline`, `frames`, `attr` est du texte de la cible sans balise à nonce ; seul le prompt le dit (`prompt.py:189-190`). `title` et `url` de `state` viennent aussi de la page. | Balise à nonce par appel. | `tests/agent/test_web.py`. |
| N17 | basse | P | `src/bh/agent/browse.py:399-401, 738-739` | Sur ce scope `bh-browse` annonce « websockets: N opened to the target » alors que le gate refuse le handshake à tout autre client que bh-browser ; « socket.io may fall back to polling » suggère un autre chemin. | Compter après le handshake ; retirer la phrase. | `tests/agent/test_browse.py`. |
| N18 | basse | P | `src/bh/classes.py:22-27` ; `src/bh/cards/xss.md:4` ; `src/bh/cards/sqli.md:4` | Reste de I8 : les cartes de classe et la ligne `Tool:` nomment des scanners refusés ici. | Variante sans scanner par carte, ou filtre à l'injection. | Étendre le test I8 à `cards_block`. |
| N19 | basse | P | `src/bh/browser_service/controller.py:834-838` | `Display.wipe` fait `rmtree(ignore_errors=True)` sans contrôle, marqueur déjà supprimé : un effacement partiel passe pour réussi. | Vérifier que le répertoire a disparu, sinon erreur. | Unitaire. |
| N20 | basse | P | `src/bh/gate/addon.py:998` | Les 429 et 503 reçus par bh-browser ne ralentissent plus le débit commun (l'exclusion dépasse la pause WAF). | N'exclure que `waf`. | Unitaire. |
| N21 | basse | P | `src/bh/agent/hooks.py:31, 112, 118` | L'exemption de troncature ne vaut que pour un `bh-web text` ou `frames` sans `( ) < > $ ; & |` : un sélecteur `:has-text("…")` retombe à 30 + 12 lignes. `outline` n'est jamais exempté. | Exempter `outline` ; découper avec `shlex` avant de refuser. | `tests/agent/test_hooks.py`. |
| N22 | basse | S | `src/bh/gate/addon.py:253-258` | bh-browser est reconnu par le nom DNS `browser`. Service arrêté, le nom part au résolveur de l'hôte. | N'accepter qu'une adresse du réseau `sandbox`. | Unitaire : une adresse hors sous-réseau est ignorée. |

## 5. Bloquants restants avant Sonnet, puis mesures live

### Bloquants, dans l'ordre

1. **B1, rotation faite et vérifiée.** `bh ui rotate-token`, `bh notify rotate`, réabonner le téléphone. Critère : l'ancien cookie rend 401, un POST sur l'ancien topic n'arrive pas.
2. **N2 / B4, détection prouvée sur la vraie page.** Au premier « Verification required » : `host.save_snapshot()`. Critère : `challenge.pending == true`, raison notée, fixture remplacée. Si `pending` est faux : corriger avant toute chasse (règle anti-bot).
3. **N3, reprise.** Corriger `wait_human` (une condition), ou appliquer le contournement : Mio ferme l'onglet `/captcha/` dès le challenge résolu, et les cartes C0 et C1 donnent la séquence. Critère : après fermeture, `bh-web state` montre `human_viewing: false` et `bh-web press Enter` rend 0.
4. **I7 + N5 + N12, ce que le chasseur lit.** Copier `out/cards/*.md` dans `src/bh/cards/`, ajouter `cards: [msrc-copilot, bh-web-manual]` au scope, réécrire la note du scope. Critère : la première tâche contient « Program cards (pinned » et les deux fiches ; `tests/test_classes.py` et `tests/test_audit_s3.py` relancés avec la nouvelle `prompt-injection.md` (non lancés ici).
5. **B6, deux identités HTTP qui marchent.** Critère : `qq <API authentifiée>` rend user-a 200 et user-b 200 sur leurs propres données, anonyme 401. Si l'API est sur substrate, N1 d'abord.
6. **Paramètres de lancement.** `--max-turns 100 --minutes 240` (défauts 60 et 30, `src/bh/cli.py:859-860`).

N4, N9 et N23 ne bloquent pas si C0 et C1 sont épinglées : elles nomment les 15 sous-commandes, remplacent `bh-browse` par `bh-web net` pour la cartographie, et lisent les refus HTTPS par `bh-web net --last N` (ligne `failure`).

### Mesures live prioritaires, dans l'ordre

| # | Mesure | Critère de succès |
|---|---|---|
| 1 | Rotation (B1) | Ancien cookie 401 ; ancien topic muet. |
| 2 | Snapshot pendant un challenge (B4, N2) | `pending == true` ; `frames` contient une URL `challenges.cloudflare.com` avec `visible` vrai ou inconnu. |
| 3 | Reprise après résolution (N3, doc 18 §7.8-3) | Le message en attente part seul ou avec une Entrée ; aucune action automatisée sur le challenge ; `human_viewing` faux moins de 10 s après la fermeture de l'onglet. |
| 4 | Identités HTTP (B6, N1) | `qq` : 200, 200, 401. Rejoué à T0+90 min. Sur substrate : `q -a user-a <route GET vue dans bh-web net>` différent de 401. |
| 5 | Durée du websocket (B8-1, I18) | Page ouverte 11 min puis un message : réponse sans nouveau challenge. À 3600 s : événement `blocked` avec `closed: true`, l'appli se reconnecte. |
| 6 | Trames client au repos (B8-2) | Moins de 6 `ws-message` `from: client` par minute ; aucun refus « websockets: 2 already open ». |
| 7 | `bh-web switch user-b` puis retour (I2) | `identity` vaut l'identité demandée en moins de 60 s ; `browser-identity.json` suit ; un challenge par bascule. |
| 8 | Canari de bout en bout (I1) | Planté par B dans `bh-web`, lu par A : événement `canary` `ws-server` ou `response-body` sous l'identité A, puis `verified-evidence`. Variante : canari en nom d'hôte hors scope → `request-url`, client `browser`, identité B. |
| 9 | `bh-web frames` sur le hub (I4) | Réponses lisibles ; aucune trame `ChallengeProof`. |
| 10 | `bh-web upload` dans le composeur (I3) | Le fichier apparaît joint, sans sélecteur de fichier natif. |
| 11 | Refus du gate en 5 min de navigation (B8-3, B8-4, I6) | Zéro « only as one of your identities » ; moins de 10 réponses 404 ; huit « New chat » en 10 min sans refus. |
| 12 | Relais Mythos depuis l'agent (I10) | Un `count_tokens` puis un message passent. Avant l'étape 3 du plan. |
| 13 | `navigator.webdriver` (doc 18 §7.8-8) | Valeur consignée. Rien n'est masqué ni ajouté. |

## 6. Cartes écrites et code à ajouter

| Carte | Fichier (`out/cards/`) | Lignes (limite) | Classe pour `--class` | Arrivée |
|---|---|---|---|---|
| C0 | `msrc-copilot.md` | 50 (60) | aucune | épinglée |
| C1 | `bh-web-manual.md` | 70 (80) | aucune | épinglée |
| C2 | `ai-conversation-isolation.md` | 40 (80) | `idor` | lue à la demande |
| C3 | `copilot-share.md` | 41 (80) | `broken-access-control` | lue à la demande |
| C4 | `prompt-injection.md` | 33 (40) | `prompt-injection` | carte de classe (choisie par la surface) |
| C5 | `ai-output-rendering.md` | 41 (80) | `xss` | lue à la demande |
| C6 | `ai-memory.md` | 39 (80) | `prompt-injection` | lue à la demande |
| C7 | `ai-file-upload.md` | 41 (80) | `file-upload` | lue à la demande |
| C8 | `ai-connectors.md` | 38 (80) | `prompt-injection` | lue à la demande, plan seulement |

Lignes épinglées : 120 (C0 + C1) dans chaque tâche. `out/cards.yaml` donne la clé `cards:` et, par carte, la classe et le code attendu.

Ce que les cartes font des contradictions et des trous du code :
- Elles suivent `BROWSER_BLOCK` après une attente expirée (une intention, pas de `bh-note blocked captcha`) : N5.
- Elles disent 4 identifiants par route et par 10 min, comme la doctrine : N11.
- Elles n'emploient jamais « MSOBB » et disent que les comptes gardent leur nom : N12.
- Elles donnent la séquence pour `human_viewing` (relire `bh-web state` à chaque tour, ne pas rappeler `wait-human`) : N3.
- Elles mettent le canari en première étiquette du nom d'hôte et lisent les refus par `bh-web net --last N` : N7, N23.
- Elles interdisent `tabs --select` pendant un challenge et le clic sur « Sign out » : N8, N14.

Aucune carte n'emploie une commande absente du code. Étapes qui dépendent d'un comportement non mesuré ou d'un défaut, avec la sortie prévue :

| Carte, étape | Dépend de | Si cela échoue |
|---|---|---|
| C1 étape 8, C2 étape 7, C4 étape 3, C6 étape 1 | `bh-web switch` (non mesuré, N13) | `bh-note fact "switch failed: …" -k dead-end`, puis `q -a` ; identité nulle : `bh-note blocked account` |
| C1 étape 9a, C0 étape 6 | `human_viewing` (N3) | relire `bh-web state` à chaque tour |
| C2 étape 5 | bearer substrate (N1) | `bh-note fact "<origin>: q -a answers 401 to the owner" -k dead-end`, variante UI |
| C1 étape 6, C2 étape 3, C8 | `bh-web frames` sur le hub (non mesuré) | `bh-web net`, ou `-k dead-end` |
| C6 étape 1 | mémoire activée sur user-b | `bh-note blocked account "memory not enabled on user-b"` |
| C7 étapes 1 et 3 | `bh-web upload` (non mesuré) | `bh-note fact "upload: …" -k dead-end` |
| C8 étapes 1 et 3 | connecteur et canal de livraison (prérequis de Mio) | `bh-note blocked account "…"` |

Code et données à ajouter, par ordre d'utilité :
1. Copier les 9 fichiers dans `src/bh/cards/` (`prompt-injection.md` remplace l'existant) et ajouter `cards: [msrc-copilot, bh-web-manual]` à `scopes/msrc/copilot.yaml`.
2. Réécrire `notes:` du scope (`scopes/msrc/copilot.yaml:136`). Texte proposé : « MSRC Copilot bounty (https://www.microsoft.com/en-us/msrc/bounty-ai). The MSRC page declares in scope 'copilot.microsoft.com and copilot.ai ... when tested using a personal account': we test our own two personal accounts only (user-a, user-b). Cross-user impact is what pays (program card). Every report gives the conversation identifier, obtained by typing /id in the conversation. Login and asset hosts are support hosts, never targets. substrate.* hosts: our own conversations only. One conversation at a time, never a flood of prompts. Cloudflare Turnstile guards message sending: never solved, evaded or worked around by the agent; the operator passes it in the agent's browser (bh-web wait-human, program card). »
3. N3 : `wait_human` attend `human_viewing == false` (`src/bh/agent/web.py:192-204`).
4. N1 : capture de `origin_headers` pour une cible à règle URL (`src/bh/accounts/enroll.py:436`, `src/bh/scope/model.py:601-610`).
5. N23 : `net --denied` garde les lignes `failure` d'un tunnel refusé (`src/bh/browser_service/controller.py:581`).
6. N4 et N5 : les 15 sous-commandes dans `BROWSER_BLOCK`, et les quatre textes « blocked captcha » alignés.
7. N7 : une phrase de doctrine après `src/bh/runner/prompt.py:148` : « A canary that leaves by a URL must be the first label of the host; the gate never sees the path of a refused https request. »

Aucun alias de classe n'est nécessaire. Un alias ne change que le nom rangé avec le finding (`src/bh/runner/ingest.py:152`), donc le standard de preuve du juge et l'exclusion du programme ; il ne rend aucune carte sélectionnable (`src/bh/classes.py:340-343`). Les cartes passent directement un identifiant existant à `--class`. `tests/test_classes.py` n'a pas à changer : la nouvelle `prompt-injection.md` garde les chaînes exigées, évite les deux interdites, tient en 33 lignes, et son titre commence toujours par « ## Indirect prompt injection » (`tests/test_audit_s3.py:138, 154`).

## 7. Traçabilité

C0 = `msrc-copilot`, C1 = `bh-web-manual`, C2 = `ai-conversation-isolation`, C3 = `copilot-share`, C4 = `prompt-injection`, C5 = `ai-output-rendering`, C6 = `ai-memory`, C7 = `ai-file-upload`, C8 = `ai-connectors`.

| Cartes | Commande ou chemin cité | `fichier:ligne` qui le définit |
|---|---|---|
| toutes | `bh-web` comme seul chemin d'envoi de prompt ; jamais d'action sur un challenge | `src/bh/runner/prompt.py:176-179` ; `src/bh/agent/main.py:45-48` |
| C0 C1 C2 C3 C6 C8 | `bh-web state` et ses champs `url`, `identity`, `challenge.pending`, `human_viewing`, `fills`, `tabs`, `switch_requested`, `switch_error` | `src/bh/agent/web.py:9, 123-124` ; `src/bh/browser_service/controller.py:509-522` |
| C0 C1 C2 | `bh-web goto <url>` | `src/bh/agent/web.py:10, 125-127` ; `src/bh/browser_service/controller.py:248, 530-535` |
| C0 C1 | `https://copilot.com/chat` | `scopes/msrc/copilot.yaml:65, 84` |
| C1 C2 C7 | `bh-web fill <css> <text>`, 2000 caractères, 1 du budget | `src/bh/agent/web.py:11, 128-129` ; `src/bh/browser_service/controller.py:71, 249, 537-542` |
| C1 C5 | `bh-web click <css>` | `src/bh/agent/web.py:12` ; `src/bh/browser_service/controller.py:250, 544-547` |
| C0 C1 C2 C7 | `bh-web press <key>` et la liste des touches | `src/bh/agent/web.py:13` ; `src/bh/browser_service/controller.py:94-112` |
| C0 C1 C2 C3 C5 C6 C7 | `bh-web wait <css\|ms>`, 30000 ms au plus, 15 s pour un sélecteur, rend l'état | `src/bh/agent/web.py:22, 130-131` ; `src/bh/browser_service/controller.py:73-74, 301-307, 554-559` |
| C0 C1 C2 C3 C6 C7 C8 | `bh-web text [--css C] [--tail N]`, 8000 en tête, 20000 en queue | `src/bh/agent/web.py:14, 137` ; `src/bh/browser_service/controller.py:65-66, 252, 561-565` |
| C0 C1 C3 C5 C6 C8 | `bh-web outline [--css C]`, 12000 caractères | `src/bh/agent/web.py:15, 138` ; `src/bh/browser_service/controller.py:68, 255, 567-569` |
| C1 C3 C5 C7 | `bh-web attr <css> <name>`, 4000 caractères | `src/bh/agent/web.py:16, 132-133` ; `src/bh/browser_service/controller.py:69, 256, 571-577` |
| toutes sauf C6 pour `failure` | `bh-web net [--last N] [--denied]`, champs `t, method, status, denied, reason, failure, url` | `src/bh/agent/web.py:17, 139` ; `src/bh/browser_service/controller.py:81, 257, 579-589, 895-907` |
| C1 C2 C8 | `bh-web frames [--last N]`, champs `t, dir, url, text`, jetons remplacés | `src/bh/agent/web.py:18, 140` ; `src/bh/browser_service/controller.py:82, 260, 610-621` ; `src/bh/browser_service/detect.py:91-132` |
| C1 C5 | `bh-web tabs [--select I]` | `src/bh/agent/web.py:19, 141` ; `src/bh/browser_service/controller.py:258, 591-602` |
| C1 C7 | `bh-web upload <css> <file>`, 256 Kio, nom sans chemin, réponse `{ok, name, bytes, mime}` | `src/bh/agent/web.py:20, 42, 106-115` ; `src/bh/browser_service/controller.py:76, 91, 259, 604-608` |
| C0 C1 C2 C4 C6 | `bh-web switch <identity>`, `switch_error`, « about 10 s », attente pendant un challenge | `src/bh/agent/web.py:21, 47-51` ; `src/bh/browser_service/controller.py:261, 623-629` ; `src/bh/browser_service/watch.py:180-207` |
| C0 C1 | `bh-web wait-human [--timeout S]`, 300 s, « cleared », « still pending » | `src/bh/agent/web.py:23, 39, 184-222` |
| C0 C1 | codes de sortie 0, 1, 3, 4 ; `human-needed`, `human-viewing`, `fill-budget`, `TimeoutError` | `src/bh/agent/web.py:170-181` ; `src/bh/browser_service/controller.py:376-390` |
| C0 C1 | écran ouvert : seules `state`, `text`, `frames` répondent | `src/bh/browser_service/__init__.py:48` ; `src/bh/browser_service/controller.py:376-378` |
| C0 | 80 `fill` par segment, 200 par identité et jour UTC | `src/bh/browser_service/controller.py:85-86, 473-484` |
| C0 C2 C6 | 4 identifiants (ou nouvelles conversations) par route et par 10 min | `src/bh/runner/prompt.py:26` |
| C0 C1 | un chargement de page = un challenge ; jamais `goto` si le chat est affiché | `src/bh/runner/prompt.py:173-175` |
| C0 C1 | reprise : `text --tail 2000`, Entrée une fois, même intention ; après expiration : intention, surface HTTP, `state` tous les 10 tours | `src/bh/runner/prompt.py:179-186` ; `src/bh/agent/web.py:43-46` |
| C0 | 15 tours de cartographie au plus | `src/bh/runner/prompt.py:266-269` |
| C1 | troncature à 80 lignes (30 + 12, chemin du fichier) ; exemption jusqu'à 24000 caractères pour `text` et `frames` seuls sur la ligne | `src/bh/agent/hooks.py:25-31, 109-136, 147` |
| C1 C2 | `grep` sur un fichier de sortie | `src/bh/runner/prompt.py:114` ; `src/bh/agent/hooks.py:134` |
| C1 | sélecteurs CSS, 300 caractères | `src/bh/browser_service/controller.py:70, 177-178, 931-932` |
| C1 | `button:has-text('New chat'), [aria-label='New chat']` | `scopes/msrc/copilot.yaml:96` |
| C1 C2 | refus `[bh-lock]` et `bh-crawl` à lancer avant | `src/bh/agent/hooks.py:58-76` ; `src/bh/agent/contract.py:58, 604, 644-648` |
| C0 C1 C2 | `bh-crawl <url>` | `src/bh/agent/tools.py:798-802` ; `src/bh/runner/prompt.py:67, 89-91` |
| C0 | `bh-recon` (à sauter) | `src/bh/agent/tools.py:800-807` ; `src/bh/runner/prompt.py:67` |
| C0 C1 C2 C3 C4 C6 C7 C8 | `q [-a ID] [-X M] [-j JSON] [-i] [-n BYTES] <url>`, chemin du corps complet | `src/bh/agent/q.py:7-13, 107-122, 149-150` |
| C0 C1 C2 C3 C6 C7 | `qq <url>` : une ligne par identité et anonyme, `==` | `src/bh/agent/q.py:10-12, 153-176` |
| toutes | `bh-note intent "<…>"` | `src/bh/agent/note.py:4, 44` |
| C1 à C8 | `bh-note fact "<titre>" -s "<…>" -e <fichier> -k recon\|dead-end\|fact` | `src/bh/agent/note.py:3, 39-43` ; `src/bh/agent/contract.py:65` |
| C6 | `bh-note fact "CANDIDATE: <title>" …` | `src/bh/runner/prompt.py:149` |
| C0 C2 C3 C4 C6 C7 C8 | `bh-note canary`, `BH-SECRET-<16 hex>` | `src/bh/agent/note.py:11, 124-126` ; `src/bh/agent/contract.py:94` |
| C0 C2 C3 C5 C6 C7 C8 | `bh-note finding … --severity … --class … --url … --proof proof.json --summary … --not-proven …` | `src/bh/agent/note.py:6-7, 48-65` ; `src/bh/runner/prompt.py:143` ; `src/bh/agent/contract.py:62` |
| C0 C2 C3 C4 C6 C7 C8 | `bh-note finding … --observation <canary> --victim … --attacker … -e <fichier>` | `src/bh/agent/note.py:8-10, 55-62, 82-105` ; `src/bh/runner/prompt.py:144-148` |
| C2 C3 C5 C6 C7 C8 | `proof.json` : rôles `setup`, `attack`, `control`, `as`, jumeau de même méthode et même URL, `expect` | `src/bh/agent/proof.py:5-20, 56-60, 139-154` ; `src/bh/runner/prompt.py:136-139` |
| C5 C7 | étape `"browse": {"xss": "<marker>"}`, ligne `xss CONFIRMED (marker <marker>)`, rejeu avec `--as` | `src/bh/agent/proof.py:22-29, 261-270` ; `src/bh/agent/browse.py:406-414` |
| C3 C5 C7 | `bh-browse <url> [--as ID] [--xss MARKER]`, marqueur de 4 à 32 caractères, `window.__bhxss` | `src/bh/agent/browse.py:3-5, 57-60, 134-157` |
| C5 | une page, un marqueur, ni `$`, ni boucle, ni `--routes` | `src/bh/agent/contract.py:585-596` ; `src/bh/runner/prompt.py:69-70` |
| toutes | `bh-note blocked third-party-data\|server-exec "<where, no content>"` | `src/bh/agent/note.py:13, 70-75` ; `src/bh/agent/contract.py:80-86` ; `src/bh/runner/prompt.py:43-45` |
| C1 C6 C8 | `bh-note blocked account "<…>"` | `src/bh/agent/contract.py:69` |
| C8 | `bh-note blocked write-needed "<…>"` | `src/bh/agent/contract.py:77` ; `src/bh/runner/prompt.py:42` |
| C4 C8 | `bh-note blocked oob-needed "<…>"` | `src/bh/agent/contract.py:78` ; `src/bh/classes.py:144` |
| C0 C1 | pas de `bh-note blocked captcha` sur ce programme | `src/bh/runner/prompt.py:186` |
| C0 C8 | `bh-note frontier` | `src/bh/agent/note.py:15, 119-123` |
| C0 | `Read /opt/bh/cards/<card>.md` | `src/bh/classes.py:348, 383` ; `container/compose.yaml:105` |
| C0 C2 C3 C5 C6 C7 C8 | `/id` tapé dans la conversation | `scopes/msrc/copilot.yaml:136` ; `docs/research/15-msrc-premier-programme.md:89` |
| C0 | `/m365Copilot/Chathub/` réservé au navigateur ; hôtes `login.*` de support ; `copilot.ai` hors du scope | `scopes/msrc/copilot.yaml:21-49` ; `src/bh/gate/policy.py:304-305, 373-376` |
| C0 | barème : Critical sans action de B, un cran dessous avec interaction, Important pour la lecture des conversations de l'autre compte, rien pour soi-même, jailbreak ou prompt système | `.claude/skills/msrc-ai-bug-bounty/SKILL.md:58-60, 74, 88-97` ; `docs/research/15-msrc-premier-programme.md:23-24` |
| toutes | champs du rapport MSRC : URL exacte, comptes, réglages, prompts mot pour mot, identifiant, k/N | `docs/research/15-msrc-premier-programme.md:45-47` ; `.claude/skills/msrc-ai-bug-bounty/SKILL.md:144-152` |
| C2 | classe `idor` | `src/bh/classes.py:56-66` |
| C3 | classe `broken-access-control` | `src/bh/classes.py:67-85` |
| C4 C6 C7 C8 | classe `prompt-injection`, k de N avec N ≥ 3, contrôle sans instruction | `src/bh/classes.py:213-234` |
| C5 | classe `xss` | `src/bh/classes.py:125-136` |
| C7 | classe `file-upload` | `src/bh/classes.py:156-164` |
| C4 C5 C7 C8 | canari en première étiquette du nom d'hôte ; requête du navigateur de la victime vers un hôte hors scope | `src/bh/gate/addon.py:543` ; `src/bh/runner/observation.py:76-78, 131-140` ; `src/bh/gate/canary.py:24` |
| C4 | un envoi du canari hors de la victime fait rejeter la preuve | `src/bh/runner/observation.py:85-94` |
| C3 | le lecteur ne lit pas le lien avant la révocation | `src/bh/runner/observation.py:72-75` |
| C5 | `<marker>.example.org` refusé par le gate (« not in scope ») | `src/bh/gate/policy.py:262` |
| C7 | ne pas cliquer « joindre » (sélecteur natif, S) | `docs/research/19-audit-mythos-2026-11-26.md:126` ; `src/bh/agent/web.py:20` |
| C1 | ne jamais cliquer « Sign out » | `src/bh/gate/addon.py:955-961` ; `src/bh/gate/session.py:305-310` |
| C1 | pas de `tabs --select` pendant un challenge | `src/bh/browser_service/controller.py:591-593, 1005-1006` |

Trois quantités des cartes ne viennent pas du code mais de moi, comme le demande la consigne sur les nombres : la répartition des 80 `fill` par surface (68 + 12), 2 `switch` par segment, 6 `upload` par segment. Aucun sélecteur ni route Copilot n'est inventé : le seul sélecteur cité vient de la recette d'enrôlement ; `textarea`, `[role="textbox"]` et `input[type="file"]` sont donnés comme HTML générique à vérifier, avec la sortie prévue s'ils ne répondent pas. La fixture `tests/fixtures/copilot_verification_required.html` est reconstruite : aucun de ses sélecteurs n'est repris.

## 8. Questions pour Mio

| # | Question | Hypothèse prise |
|---|---|---|
| 1 | Fermes-tu l'onglet `/captcha/` dès le challenge résolu, tant que N3 n'est pas corrigé ? | Oui. Les cartes attendent `human_viewing: false` en relisant `bh-web state`. |
| 2 | Hôtes `sso` : garder le refus de tout GET pour l'agent (N9), ou déclarer `get_paths` pour `authorize` et `savedusers` ? | Refus gardé pour Sonnet. Les cartes cartographient par `bh-web net`, pas par le HAR de `bh-browse`. |
| 3 | Répartition du budget (68 `fill` sur 80, 12 de réserve), 2 `switch` et 6 `upload` par segment : te vont-ils ? | Oui. Chaque `switch` te coûte un challenge. |
| 4 | L'identité attaquante peut-elle écrire sur un objet de test de l'autre compte (C2 étape 8, C3 étape 7) ? La doctrine le permet (les deux comptes sont à nous). | Oui, une requête par route, sur une conversation créée pour le test. |
| 5 | Charges à marqueur sur nos propres pages partagées et fichiers (`window.__bhxss`, SVG à script) : acceptables pour MSRC ? | Oui : marqueur bénin, objets à nous, supprimés après le test. |
| 6 | Hôte hors scope nommé dans les charges : `example.org` (jamais joint, le gate refuse le tunnel). Préfères-tu un domaine à toi ? | `example.org`, rien ne sort. |
| 7 | Épingler aussi `prompt-injection` pour Opus et Mythos (33 lignes plus le standard par tâche) ? | Non : choisie par la surface, lisible sous `/opt/bh/cards/`. À épingler si elle manque dans la tâche d'un segment. |
| 8 | Gravité : « Important » MSRC = `--severity high`, « Critical » = `critical` ? | Oui. |
| 9 | Mémoire : user-b seulement, ou les deux comptes pour le contrôle ? | user-b seulement. Sous Sonnet, C6 s'arrête sur `blocked account`. |
| 10 | Connecteurs : lequel, et quel canal de livraison de user-a vers user-b ? | Aucun pour Sonnet et Opus : C8 reste un plan. |
| 11 | La sonde sans `expect` ne dit pas quel compte répond. Existe-t-il une page d'API qui rend l'adresse du compte ? | Non connue : à noter par le chasseur (`bh-web net`), puis à ajouter en `expect`. |
| 12 | `copilot.ai` : toujours hors du scope YAML ? | Oui, et chaque rapport dit que le test a eu lieu sur `copilot.com` après la redirection. |

