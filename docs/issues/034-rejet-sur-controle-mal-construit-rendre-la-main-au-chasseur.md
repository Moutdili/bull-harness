---
id: 34
title: "Rejet sur contrôle mal construit : rendre la main au chasseur"
labels: [P1, area:verify, owner:claude, build]
status: open
---

# Rejet sur contrôle mal construit : rendre la main au chasseur

Chasse 2 du 2026-11-25 sur Juice Shop : F6 (adhésion deluxe gratuite) et F10 (inscription avec rôle admin),
deux vraies failles connues du lab, ont été rejetées par l'étage A (« the control answered exactly like the
attack »). Le contrôle écrit par le chasseur ne différait pas de l'attaque sur le marqueur choisi : la preuve était
mal construite, la faille pas forcément absente. Le rejet est définitif et le chasseur n'en sait rien.

Piste : `control_disproves` reste un rejet de la preuve, mais le finding passe `needs-proof` (pas `rejected`), un
fait est écrit pour le chasseur (« F<n> : le contrôle répond comme l'attaque, choisis un marqueur que seul
l'attaquant obtient »), et une preuve corrigée relance la vérification, une fois.

**Acceptation :** test : preuve à contrôle identique → statut `needs-proof` + fait pour le chasseur ; nouvelle
preuve valide → vérifiée ; deuxième échec → `rejected`.

Plan : [docs/plan-v3.md](../plan-v3.md)
