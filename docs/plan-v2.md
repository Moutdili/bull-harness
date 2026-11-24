# Plan v2 : ce que les autres ont, en mieux (2026-11-24)

Recherche : vérificateur de Xalgorix (`internal/agent/verifier.go`, Apache-2.0, lu via l'API GitHub),
validateurs déterministes de XBOW (Dark Reading, XBOW), skills `hunt-*` de Claude-BugHunter (MIT),
double graphe d'ARTEX (README), stack d'observabilité de PentAGI (README), conventions OpenTelemetry GenAI
(statut « Development » en 2026). Contexte plateformes : suspension Bugcrowd de 30 jours après
10 rapports invalides consécutifs ; HackerOne et curl ont suspendu des bounties à cause de l'« AI slop ».
Règle inchangée : on porte des idées, pas du code.

| Brique | Chez eux | Leur limite | Chez nous (amélioration) |
|---|---|---|---|
| **Classes de vuln** (socle commun) | Listes éparses : skills d'un côté, critères du vérificateur de l'autre | Le chasseur et le vérificateur n'appliquent pas la même norme de preuve | Un module `bh.classes` : alias, signaux de surface, **norme de preuve**, partagé par la doctrine, les fiches, le vérificateur et `forbidden_vulns` |
| **Vérificateur** | Xalgorix : agent LLM sceptique, 8 tours, 3 min, verdicts confirmed / rejected / inconclusive. XBOW : validateurs déterministes, parce que la validation LLM était peu fiable | Xalgorix : 100 % LLM, la preuve est du texte libre. XBOW : fermé | **Deux étages.** A) rejeu déterministe d'une preuve structurée (`proof.json` : requêtes, attendus, **contrôle négatif obligatoire**), deux fois, à travers le gate. B) relecteur LLM au contexte neuf, outils en lecture, borné, qui juge le sens (par design ? mauvaise classe ?). `verified` seulement si A reproduit et B confirme ; `rejected` seulement si réfuté ; sinon `inconclusive` → todo. Dédup contre nos findings, et **PoC triager générée** depuis la preuve rejouée (placeholders `TOKEN_A`, jamais `X-BH-Identity`) |
| **Fiches de méthode** | 82 skills de plusieurs centaines de lignes ; le modèle choisit | Coût en tokens, choix laissé au modèle, aucun lien avec la vérification | 12 fiches courtes (≤ 40 lignes) écrites par nous ; **sélection par le runner** d'après les signaux de la surface (ids dans les routes, `/graphql`, paramètres `url=`, upload…), 3 au plus par segment ; chaque fiche finit par sa norme de preuve (la même que le vérificateur) |
| **Graphe d'assets** | ARTEX : graphe d'assets + graphe d'exploration reliés par des ancres ; le scope « définit le dénominateur » ; gate de cible désactivé par défaut | Les assets découverts peuvent entrer dans le scope | Tables `assets` / `coverage` / `tested` / `asset_links` dans le board (hôte = autorité). Chaque asset est passé à `scope.check()` à l'insertion ; un hôte hors scope découvert → todo `scope-question`, jamais dans le scope. Le « testé » vu par le gate prime sur ce que dit l'agent. Remplace la surface éparpillée (piste C2 de la revue) |
| **Observabilité** | PentAGI : Grafana, VictoriaMetrics, Jaeger, Loki, Langfuse, ClickHouse… (~10 conteneurs) | Lourd ; ne relie pas les tokens aux findings | Zéro conteneur en plus : par tour (tokens, cache, outil, durée), par run (requêtes gate, refus, 429), par finding (coût, verdict). Onglet « Métriques » de l'UI. Export OTLP plus tard (conventions encore instables) |

## Ordre (le plus utile avant une vraie cible d'abord)

1. `bh.classes` + 12 fiches + sélection par signaux. Critère : sur Juice Shop, la fiche IDOR est chargée (routes à id) et la fiche SQLi aussi (paramètre `q`) ; tests unitaires de sélection.
2. Vérificateur A + B, dédup, PoC triager. Critères : un finding sans contrôle négatif est refusé à l'écriture ; une preuve fausse (contrôle qui répond pareil) → `rejected` ; une vraie IDOR Juice Shop → `verified` ; tests unitaires de l'étage A sur un serveur local.
3. Graphe d'assets dans le board, surface rendue depuis le board. Critères : un hôte hors scope découvert crée une todo ; le frontier hôte et `bh-note frontier` affichent les mêmes chiffres.
4. Observabilité : tables `turns`, compteurs gate par run, onglet Métriques. Critère : coût par finding vérifié affiché pour les runs lab.
