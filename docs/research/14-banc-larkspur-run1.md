# 14 — Banc Larkspur, première mesure (2026-11-25)

Cible inédite (`lab/bench/`, grille `lab/bench/ANSWERS.md` jamais montée), 7 failles plantées, 3 leurres.
Chasse : `bh hunt scopes/lab/bench.yaml --hours 1.5 --max-turns 30 --minutes 20` après `bh board reset lab-bench`.
Runs 52 à 60 : 9 segments, 117 tours, chasse $1.94 + juge $1.22 éq. Comptes créés seuls (`self_signup`).

| Faille | Trouvée | Statut | Note |
|---|---|---|---|
| V1 IDOR lecture | oui | F17 `verified` (F16 doublon `inconclusive`) | ref fuitée par le planning, trouvée |
| V2 IDOR écriture (PATCH réservation) | non | — | non tentée |
| V3 SQLi booléenne `sort` | oui | F19 `verified` | |
| V4 XSS DOM `/#/join` | non | — | route absente des liens, jamais découverte |
| V5 XSS stocké `display_name` | non | — | formulaire vu, pas testé ; XSS tenté sur le titre des réservations (sain) |
| V6 quantité négative | oui | F18 `inconclusive` | rejeu impossible : créneau fixe déjà pris (issue 35) ; le juge a confirmé |
| V7 fuite `/status?detail=full` | non | — | paramètre non découvert |
| L1-L3 leurres | — | 0 faux positif | |

Rappel 3/7 (43 %), vérifiées 2/7 ; précision 4/4 findings vrais (dont un doublon), 0 sur les leurres.

Ce que ça dit :
- Le harnais tient de bout en bout sur une cible inconnue : comptes, rejeu, juge, 0 faux positif.
- Les manques sont de la méthode : écritures croisées (V2), champs stockés rendus ailleurs (V5), routes et paramètres
  absents des liens (V4, V7). Pistes : fiche « stored XSS : tout champ affiché à un autre utilisateur », extraction des
  routes de la table du routeur JS par `bh-crawl`, `bh-params` sur les endpoints de statut, et une passe IDOR en écriture
  systématique avec les deux identités.
- Deux défauts du rejeu trouvés par ce banc (écritures rejouées deux fois, état persistant) : `c7e70a5`, issue 35.

## Deuxième mesure (même jour, après les correctifs de l'audit 13)

Même cible remise à zéro, mêmes paramètres. Runs 61 à 68 : 8 segments, 108 tours, chasse $1.77 + juge $0.41 éq.

| Faille | 1ʳᵉ mesure | 2ᵉ mesure |
|---|---|---|
| V1 IDOR lecture | vérifiée | vérifiée (F16) |
| V2 IDOR écriture | non trouvée | **vérifiée** (F19, après `needs-proof` : preuve refaite par le chasseur) |
| V3 SQLi `sort` | vérifiée | vérifiée (F18) |
| V6 quantité négative | trouvée, non rejouable | **vérifiée** (F17, créneau frais, écritures rejouées une fois) |
| V4, V5 XSS, V7 fuite | non trouvées | non trouvées |
| leurres | 0 faux positif | 0 faux positif ; F20 classé doublon de F19 |

Rappel vérifié 4/7 (contre 2/7), précision 4/4, coût total $2.18 éq. (contre $3.16). Todo humaine : 4 `submit`, rien d'autre.
Relais filtré (audit H1) validé sur toute la chasse : 0 refus, 122 réponses 200 ; `anthropic-beta` réellement envoyés par
Claude Code 2.1.330 : `claude-code-20250219`, `oauth-2025-04-20`, `interleaved-thinking-2025-05-14`,
`context-management-2025-06-27`, `per-turn-control-2026-07-01`, `mid-conversation-tool-changes-2026-07-01`,
`thinking-token-count-2026-05-13`, `effort-2025-11-24`, `thinking-display-updates-2026-08-18`, `extended-cache-ttl-2025-04-11`.
Restent à gagner : les XSS (V4 route hors liens, V5 champ stocké rendu ailleurs) et les paramètres cachés (V7).
