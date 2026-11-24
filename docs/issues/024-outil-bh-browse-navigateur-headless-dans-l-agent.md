---
id: 24
title: "Outil bh-browse : navigateur headless dans l'agent"
labels: [P0, area:autonomy, owner:claude, build]
status: open
---

# Outil bh-browse : navigateur headless dans l'agent

Playwright Python + chrome-headless-shell au build, CA du gate dans NSS, un navigateur par commande. Ressources hors scope bloquées localement (décision Mio 2026-11-25), comptées dans le résumé. Plan : docs/research/09-vision-headless.md §4-5.

**Acceptation :** sur Juice Shop : `bh-browse` sort ≤ 25 lignes, ajoute ≥ 1 route SPA absente de endpoints.jsonl, `--xss` confirme le XSS DOM connu ; journal du gate : 0 requête hors lab

Plan : [docs/plan-v3.md](../plan-v3.md)
