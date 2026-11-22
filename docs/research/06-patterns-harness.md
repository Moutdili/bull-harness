# 06 — Patterns à porter dans bull-harness (synthèse Claude, 2026-11-22)

Source : `02-frameworks-agentiques.md`, `03-repos-et-outils.md` (Hermes) + `00-veille.md`.
Règle : on porte des **patterns**, pas du code. ARTEX, Cairn et Shannon sont **AGPL-3.0** : copier leur code contaminerait le harnais.

## Pattern → requirement

| Pattern | Origine | Req | Ce qu'on prend | Ce qu'on refuse |
|---|---|---|---|---|
| Blackboard **fait / intention / hint**, workers sans rôle, coordination par le tableau | Cairn (AGPL) | R3, R1 | Mémoire partagée compacte : l'agent lit des faits, pas des logs bruts. Rotation de scope = changer de tableau. | Prompts qui interdisent au modèle de refuser ; redispatch d'une tâche refusée vers un autre worker. |
| Workers = **CLI d'agents de code** (Claude Code) dans des conteneurs Kali | Cairn | R5, R2 | Moteur = `claude` headless dans le conteneur, interchangeable. | — |
| **Session authentifiée enregistrée par l'humain** (captcha/OTP résolus une fois) puis rejouée par les agents | ARTEX (AGPL) | R4 | Todo humaine « auth » : l'humain se connecte dans un navigateur, le harnais capture cookies/headers et les injecte dans le scope. | Ajout automatique des actifs découverts au scope. Chez nous, un actif découvert va dans la todo humaine, jamais dans le scope. |
| **Reflector** : relance un agent qui arrête d'appeler des outils | PentAGI (MIT) | R3 | Détecteur de stagnation qui déclenche la rotation de scope. | Répondre « dans la voix de l'utilisateur ». Le reflector est un message système explicite. |
| Sandbox Docker **par flow** | PentAGI | R2 | Un conteneur par scope/run. | Montage du socket Docker dans l'agent : c'est la classe de CVE-2026-14784. |
| **Recettes d'outils en YAML** (100+) | CyberStrikeAI (Apache-2.0) | R2 | Format plugin : un YAML déclare la commande, les args, le filtre de sortie et l'alias. | C2, WebShell, skills de contournement de rate-limit, bascule Tor, anti-forensics : hors périmètre bug bounty. |
| Bridges chat (Telegram/Slack/Discord) | CyberStrikeAI | R4 | Canal de notif en plus de Gmail. | — |
| **Serveur MCP 150 outils**, `apt install hexstrike-ai` | HexStrike (MIT) | R2 | L'arsenal est disponible dans Kali en une commande. | Charger 150 schémas MCP dans le contexte, ce qui coûte des milliers de tokens à chaque tour (contraire à R1). On expose des CLI + builtins ; MCP seulement à la demande. |
| **Vérificateur qui ré-exploite** chaque finding | Xalgorix | R4 | Étape obligatoire avant la todo humaine (cf. suspension Bugcrowd 30 j). | — |
| Sortie filtrée + **pointeur vers le brut** | rtk | R1 | Contrat des builtins : résumé ≤ N lignes + chemin du log complet. | — |

## Ce que les 5 frameworks ne font pas (notre différenciation)

1. **Autorisation appliquée dans le code.** Aucun des cinq ne le fait (Hermes, 02). Chez nous : scope en dur + proxy de sortie allowlist + refus au niveau réseau.
2. **Trafic identifiable, pas furtif.** Les signaux de détection listés en 02 (pas de jitter, rafales) ne sont pas un problème à corriger par évasion. On respecte le rate-limit du programme et on ajoute l'en-tête d'identification qu'il exige.
3. **Refus du modèle = information.** Un refus est journalisé et remonte dans la todo humaine. Il n'est jamais contourné.

## Hors périmètre harnais dans le dossier Hermes

`04-plan-detection-lab.md`, `05-carriere-stage-suisse.md` et la section « Ce qui manque encore » du README (Sigma, SPL/KQL, dataset, faux positifs) relèvent du projet détection, pas du harnais bug bounty.
