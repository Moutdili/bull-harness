---
id: 32
title: "Historique d'URL passif (gau / waymore) dans bh-recon"
labels: [P1, area:autonomy, owner:hermes, build]
status: open
---

# Historique d'URL passif (gau / waymore) dans bh-recon

Source : revue de https://aibugbounty.beacon.host/ (liste curatée, 2026-11-25). 13 des 20 CLI listées sont déjà
dans l'image ; manquent gau, waymore, waybackurls, paramspider, gf, linkfinder, gowitness, interactsh-client.
Retenus : gau ou waymore (URL et paramètres historiques via Wayback, CommonCrawl, OTX, urlscan, déjà sur la liste
passive du gate), et les motifs gf (classement hors ligne des paramètres). Écartés : linkfinder (bh-crawl a son
extracteur JS), gowitness (bh-browse --shot), paramspider (doublon de gau), interactsh (issue 31).
Versions épinglées et build depuis la source : la page propose des installations `curl | bash`.

**Acceptation :** `bh-recon` sur un domaine du scope ajoute des endpoints de source `archive` à endpoints.jsonl,
GET seulement vers les hôtes passifs (journal du gate), sortie ≤ 25 lignes.

Plan : [docs/plan-v3.md](../plan-v3.md)
