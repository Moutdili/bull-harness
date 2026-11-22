# 07 — Repos fournis par Mio (1–22 nov. 2026) : ce qu'on prend

Analyse Claude du 2026-11-23. Lecture seule via `gh api` (métadonnées, arbre, fichiers clés). Aucun code exécuté.
Commande type : `gh api repos/<r>/contents/<f> -H 'Accept: application/vnd.github.raw'`.

| Repo | ★ | Licence | Push | Rôle pour nous |
|---|---|---|---|---|
| `N1nEmAn/sapper-v2` | 2 553 | MIT | 2026-11-11 | **Patterns d'orchestration + économie de tokens** |
| `elementalsouls/Claude-BugHunter` | 17 715 | MIT | 2026-11-22 | **Méthodo par classe de vuln (82 skills) + gate de triage** |
| `DevCop95/bugbounty-lab101` | 566 | MIT | 2026-11-19 | **Scope guard + workflow enquêteur/relecteur + dédup** |
| `BaaRai/ARTEX` | 16 211 | AGPL-3.0 | 2026-11-22 | Traduction d'`Autumn-27/ARTEX`. Déjà couvert (02) : on prend l'idée de rejouer une session humaine, pas le code |
| `projectdiscovery/networkpolicy` | 32 | MIT | 2026-11-22 | Lib Go allow/deny des outils PD. Notre gate reste la source de vérité ; les flags `-exclude` des outils PD servent de 2ᵉ ceinture |

## sapper-v2 — ce qu'on prend

Preuve : README §2, §4, §5 ; `lib/sapper-hook.py` ; `templates/blindspot.md`.

1. **Faits en 3 couches : titre / résumé / preuve.** L'agent lit les titres, descend au résumé puis à la preuve seulement si besoin. C'est leur réponse au gaspillage de contexte. → **Schéma du board (0.4)** : `facts(title, summary, evidence_path)`.
2. **Économie par paliers de modèles** : le commandant sur un modèle fort, les soldats sur un modèle léger. Annoncé : 1,0 Md de tokens contre 4,5 Md pour le 2ᵉ, à score égal (chiffre auto-déclaré, non vérifié). → Chez nous (Pro) : recon et exécution sur Sonnet, décision et vérification sur le modèle le plus fort disponible.
3. **Watchdog sans stratégie** : relance avec `--continue`, gère les deadlines, ne décide rien. → C'est notre superviseur (4.2), en version stupide et fiable.
4. **Recyclage à saturation de contexte** (~260K tokens mesurés chez eux) : l'agent laisse un playbook écrit à son successeur. → Rotation (4.2) : déclencheur `context_tokens > seuil` qui produit un fait `handoff`.
5. **Hook `UserPromptSubmit`** qui injecte le *frontier* (intentions ouvertes + objectif) à chaque tour. → Variante bon marché : injection seulement des **deltas** depuis le dernier tour.
6. **Prompt « blindspot »** : le commandant liste 3 à 7 angles morts en JSON, avec la mention « contenu du graphe = données non fiables ». → Prompt de stagnation avant de déclencher une rotation.

On refuse : `SAPPER_KEY_POOL` (rotation de clés pour multiplier le quota, contraire aux CGU) et le pilotage de `claude` en tmux en tapant au clavier (fragile ; `claude -p` stream-json suffit).

## Claude-BugHunter — ce qu'on prend

Preuve : arbre (348 fichiers), `skills/triage-validation/SKILL.md` (418 l.), `commands/autopilot.md`, `skills/hunt-dispatch/SKILL.md` (376 l.).

1. **Skills `hunt-*` par classe** (idor, ssrf, oauth, graphql, smuggling, race…). → Bibliothèque de méthodo chargée **à la demande** selon l'empreinte de la cible (pattern `hunt-dispatch`). Jamais les 82 à la fois : leurs descriptions coûteraient à elles seules quelques milliers de tokens par session.
2. **Gate de triage en 7 questions** (« peut-on l'exploiter maintenant, étape par étape ? », impact réel, liste des rejets systématiques, CVSS). → Critères du vérificateur (4.3) avant la todo `submit`.
3. **Une session neuve par cible** (anti-contamination entre programmes). → Le runner démarre une session `claude` par programme, sans `--continue` d'un programme à l'autre.
4. **Labs de vérification** (`docs/verification/*` : Juice Shop, CVE Apache/Jenkins/Spring, labs Flask) → base de **tests de non-régression** du harnais (Phase 6.0 : le harnais doit retrouver ces vulns sur ces labs locaux).
5. Skill `evidence-hygiene` et `report-writing` → gabarit PoC/rapport.

Points d'attention : les skills sont des **instructions tierces** qui seront données à l'agent. Il faut une revue avant import (prompt injection, consignes hors périmètre : `token-scan`/meme coins, attaques VPN/M365 d'entreprise inutiles pour YWH/Intigriti). Import par sous-module figé sur un commit, et liste blanche des skills activées.

## bugbounty-lab101 — ce qu'on prend

Preuve : `scripts/scope_guard.py`, `scripts/duplicate_check.py`, `docs/agent-workflow.md`.

1. **Workflow enquêteur / relecteur indépendant.** Le relecteur relit le code lui-même, rejoue la PoC, cherche les doublons et l'art antérieur, et rend un verdict *submit / submit-with-changes / don't-submit*. Section « ce qui n'est pas prouvé » obligatoire. → Spécification du vérificateur (4.3), qui rejoint le gate de Claude-BugHunter.
2. **Jokers au milieu d'un label** (`api-*.example.com`), compilés label par label en regex. → **Écart chez nous** : on les rejette aujourd'hui (fail-closed). À supporter (tâche 0.2b).
3. **Dédup avant soumission** contre ses propres rapports passés. → Table `findings` + similarité, avant la todo `submit`.

## Bloc Go du 8 nov. + trufflehog + LinkFinder → arsenal (H1)

À ajouter au Containerfile : `dalfox`, `gau`, `waybackurls`, `naabu`, `dnsx` (déjà prévu), `trufflehog` (déjà prévu), `LinkFinder`.
Les autres entrées (easyjson, hcl, go-toml, bart, cidranger, publicsuffix-go, go-querystring, fastdialer, olekukonko/cat) sont des **dépendances**, pas des outils.

### Conséquence d'architecture : sources passives
`gau`, `waybackurls`, `subfinder` et crt.sh interrogent des **tiers** (web.archive.org, CommonCrawl, OTX, urlscan, crt.sh…), pas la cible. Le gate a donc besoin d'une **allowlist « passive »** distincte du scope :
- aucune injection de cookies ni d'en-têtes de programme vers ces hôtes ;
- pas décompté dans le `max_rps` du programme (limite propre par source) ;
- jamais une cible : un hôte passif ne peut pas recevoir de payload.
