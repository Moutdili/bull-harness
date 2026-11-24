---
id: 31
title: "Outil bh-oob : tests hors bande (oob_allowed)"
labels: [P2, area:gate, owner:claude, build]
status: open
---

# Outil bh-oob : tests hors bande (oob_allowed)

Décision Mio 2026-11-25 : autorisation programme par programme. Exige un serveur public hors du gate. En attendant : blocker oob-needed.

**Acceptation :** champ de scope `oob_allowed` (null = interdit) ; serveur interactsh public à Mio ; un programme sans oob_allowed refuse bh-oob

Plan : [docs/plan-v3.md](../plan-v3.md)
