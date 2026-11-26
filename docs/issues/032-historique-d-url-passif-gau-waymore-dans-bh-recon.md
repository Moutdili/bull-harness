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

## Implémentation (2026-11-25, en attente de la validation live)

- **Outil : gau 2.2.4** (release amont, SHA256 de `gau_2.2.4_checksums.txt`, amd64 et arm64, Containerfile étape 4b).
  Le paquet Kali `getallurls` est gau 1.0.7 (https://www.kali.org/tools/getallurls/) : pas d'urlscan, pas de
  `--timeout` ni de `--config`. Il est retiré de packages.txt. waymore est écarté : il télécharge aussi les pages
  archivées et interroge VirusTotal et Intelligence X, qui ne sont pas des sources passives du gate.
- **Fournisseurs : wayback, otx, urlscan** (`--providers` et `providers` du fichier de config). commoncrawl est
  exclu : gau 2.2.4 lit `http://index.commoncrawl.org/collinfo.json` (pkg/providers/commoncrawl/commoncrawl.go:32),
  donc un CONNECT vers le port 80 que le gate refuse (passif = 443 seulement, policy.py `classify_connect`). Ajouter
  ce port aux sources passives réactiverait commoncrawl.
- **Proxy** : le client fasthttp de gau ignore `HTTP(S)_PROXY` (runner/flags/flags.go:46-60). bh-recon passe donc
  `--proxy http://gate:8080` (tunnel CONNECT). gau n'envoie que des GET (pkg/httpclient/client.go), sans en-tête du
  programme. Il désactive la vérification TLS (`InsecureSkipVerify`), ce qui n'a pas d'effet derrière la MITM du gate.
- **Config** : un `gau.toml` est écrit dans le dossier brut de chaque exécution et passé par `--config`. Le fichier
  `~/.gau.toml` de l'agent n'est donc jamais lu (il pourrait rediriger urlscan ou otx vers un autre hôte).
- **gf** : les motifs de tomnomnom/gf@dcd4c361 (examples) et de 1ndianl33t/Gf-Patterns@f686f06a sont copiés dans
  `/opt/bh/gf`. bh-recon les applique lui-même, avec la sémantique de `gf <nom>` : `(p1|p2|…)`, insensible à la
  casse avec `-i`. Le binaire gf n'est pas installé : il n'a pas de release et demanderait Go.
- **bh-recon** : nouvelle étape archive, dont les lignes viennent en tête du résumé (≤ 25 lignes).
  - Domaine demandé : la cible. `--subs` est ajouté quand une règle du scope vise des noms en dessous.
  - Filtre local : le `scope.yaml` poussé dans BH_DIR (l'exclusion l'emporte). Sans ce fichier, seuls le domaine
    et ses sous-domaines sont gardés.
  - Une entrée par famille de route et par origine dans `endpoints.jsonl`, avec la source `archive` et les
    paramètres fusionnés. La phase `archive` est notée dans la couverture.
  - Le résumé donne un compte gf par classe : sqli, xss, ssrf, redirect, idor, lfi, rce, ssti.
  - Le brut reste sur disque : `gau.txt`, `archive-inscope.txt`, `gf-<classe>.txt`, `gau.err`, `cmd.txt`.
  - Bornes : `--max-urls` (10 000 par défaut ; gau est arrêté à ce seuil), 120 s au plus, `--no-archive`.
  - Aucune page archivée n'est téléchargée : gau n'interroge que les index (CDX, url_list, search).
  - Sans gau, l'étape est ignorée avec une ligne d'explication.
- Tests sans réseau : `tests/agent/test_tools_archive.py`.

Validation live après `uv run bh up --build`, dans le conteneur agent (`podman exec -it --user hunter bh-agent bash`) :
`/opt/bh/check.sh | grep -E 'gau|gf'`, puis `bh-recon <domaine du scope>` : une ligne `archive: N URLs …` et une
ligne `gf (…)`, des entrées `"source": "archive"` dans endpoints.jsonl, et dans le journal du gate uniquement des
GET vers web.archive.org, otx.alienvault.com et urlscan.io.
