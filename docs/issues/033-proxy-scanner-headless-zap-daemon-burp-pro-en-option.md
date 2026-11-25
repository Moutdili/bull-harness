---
id: 33
title: "Proxy-scanner headless : ZAP daemon (Burp Pro en option)"
labels: [P1, area:autonomy, owner:claude, build]
status: closed
---

# Proxy-scanner headless : ZAP daemon (Burp Pro en option)

Recherche du 2026-11-25 :
- **Burp Pro** démarre en headless (`java -Djava.awt.headless=true -jar burpsuite_pro.jar`, config par fichier,
  Java 21) ; la REST API lance des scans ; pas d'Intruder ni de rapport en headless. Licence payante. Le serveur MCP
  BApp exige l'interface graphique ; le MCP « DAST » vit dans Burp Suite DAST (serveur payant).
- **Caido CLI** est headless et piloté en GraphQL (PAT) ; schéma sans garantie de stabilité ; enregistrement de
  l'instance en ligne (sortie vers caido.io à autoriser).
- **ZAP** (Apache 2.0) tourne en daemon (`zap.sh -daemon`), API REST complète, image `ghcr.io/zaproxy/zaproxy:stable`,
  scanner actif, spider et AJAX spider ; MCP communautaire `dtkmn/mcp-zap-server`. Aucun compte, aucune licence.

Choix : ZAP daemon en builtin `bh-zap` (classé scanner), **devant** le gate (agent → ZAP → gate → cible) pour que
scope, débit, en-têtes et identités restent appliqués ; API liée à 127.0.0.1 avec clé ; sortie ≤ 25 lignes, alertes
brutes sur disque. Burp Pro au même emplacement si Mio prend une licence (même builtin, autre moteur).
Collaborator / OOB de ZAP ou Burp : coupés (sortie hors gate), voir issue 31.

**Acceptation :** `bh-zap http://10.231.0.10:3000/ --as user-a` sur le lab : ≥ 1 alerte moyenne ou haute,
toutes les requêtes visibles dans le journal du gate, 0 requête hors scope, programme sans scanners → refus [bh-rules].

Plan : [docs/plan-v3.md](../plan-v3.md)
