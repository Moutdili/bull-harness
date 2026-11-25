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
