#!/usr/bin/env bash
# Crée les labels et les issues du plan v3 (docs/plan-v3.md) sur Moutdili/bull-harness.
set -euo pipefail
R=Moutdili/bull-harness
lab() { gh label create "$1" -R "$R" --color "$2" --description "$3" --force >/dev/null; echo "label $1"; }
lab P0 b60205 "Avant le premier run YWH"
lab P1 d93f0b "Juste après"
lab P2 fbca04 "Plus tard"
for a in tokens gate verify autonomy scope cve ops docs; do lab "area:$a" 1d76db "Domaine $a"; done
lab owner:claude 5319e7 "Claude, en direct"
lab owner:hermes 0e8a16 "Swarm Hermes"
lab owner:mio c2e0c6 "Mio (humain)"
lab measure bfd4f2 "Mesurer avant de décider"
lab build 0052cc "À construire"
lab research-check f9d0c4 "Doctrine vs littérature"
lab audit 5c2d91 "Audit"

iss() { # titre labels acceptation contexte
  gh issue create -R "$R" --title "$1" --label "$2" --body "$(printf '%s\n\n**Acceptation :** %s\n\nPlan : docs/plan-v3.md' "$4" "$3")" ; }

iss "Mesurer un segment long sur le lab (100 tours)" "P0,area:tokens,owner:claude,measure" \
  "tableau par tour publié dans docs/research/ ; part des observations et nb de réécritures de cache chiffrés" \
  "Courbe du contexte, part des observations (84 % chez SWE-agent, arXiv:2508.21433), réécritures de cache, durée des outils. Aujourd'hui : base 8-10 k, pic 19 k sur 22 tours."
iss "Vérifier le TTL du cache de prompt en OAuth (5 min ou 1 h)" "P0,area:tokens,owner:claude,measure" \
  "champ de TTL lu dans un flux du relais ; décision écrite" \
  "Nos outils durent jusqu'à 267 s, proche du TTL de 5 min. ENABLE_PROMPT_CACHING_1H serait sans effet en OAuth (sources tierces)."
iss "Isoler le juge dans son propre conteneur" "P0,area:verify,owner:claude,build" \
  "le juge ne voit ni /work du chasseur ni ses processus ; F1 revérifié" \
  "Point ouvert de la revue Mythos. Le juge lit du texte de la cible (arXiv:2507.08794, 2508.21669)."
iss "Lab d'injection de prompt contre le chasseur et le juge" "P0,area:gate,owner:claude,build" \
  "chaque variante est ignorée ou bornée par le gate ; résultat consigné" \
  "Page leurre façon Mantis (arXiv:2410.20911) + 3 variantes CAI (arXiv:2508.21669) servies par le lab."
iss "Reconstruire l'image agent depuis la base épinglée" "P0,area:ops,owner:hermes,build" \
  "check.sh vert ; liste des versions d'outils dans le repo" "Point ouvert de la revue."
iss "Lire les règles hunter YWH sur l'automatisation et l'IA" "P0,area:scope,owner:mio,research-check" \
  "extrait cité dans docs/premiere-cible-ywh.md" \
  "Aucune règle publique trouvée côté hunter ; Bugcrowd suspend 30 jours pour soumissions IA non validées."
iss "Run sur l'app perso de Mio (6.1)" "P0,area:ops,owner:claude,owner:mio,build" \
  "run complet, HAR audité, zéro requête hors scope" "Premier test HTTPS par nom, hors lab."
iss "Audit Mythos du plan, de la doctrine et du code" "P0,area:verify,owner:claude,owner:mio,audit" \
  "rapport écrit ; points critiques traités ou acceptés par Mio" "Après les autres P0, avec docs/plan-v3.md en entrée."
iss "Choisir le premier programme YWH" "P0,area:scope,owner:mio" \
  "scope YAML validé par Mio (automation_allowed, scanners_allowed)" "Voir docs/premiere-cible-ywh.md."
iss "Masquage des anciennes observations ou rotation sur seuil de contexte (4.2b)" "P1,area:tokens,owner:claude,build" \
  "à contexte égal, coût par tour -30 % sur le lab sans perte de findings" "Selon la mesure P0. arXiv:2508.21433, 2510.00615."
iss "Budget par piste et abandon chiffré" "P1,area:autonomy,owner:claude,build" \
  "une piste qui dépasse son budget devient un dead-end ; test lab" "Estimation de difficulté, arXiv:2602.17622."
iss "Routage de modèle par segment (cartographie légère, exploitation forte)" "P1,area:tokens,owner:claude,build" \
  "coût par finding vérifié sur le lab, avant / après" "arXiv:2602.21227, 2609.32917, 2609.22951."
iss "Sommeil quota calé sur l'heure de reset" "P1,area:autonomy,owner:claude,build" \
  "test avec message de quota simulé" "Aujourd'hui : 30 min fixes."
iss "Métrique « soumissions valides »" "P1,area:verify,owner:claude,build" \
  "colonne dans le board, affichée dans l'UI" "ARTEMIS : 82 % valides (arXiv:2512.09882)."
iss "Jokers en milieu de label et suffixes publics (0.2b)" "P1,area:scope,owner:claude,build" "tests de 0.2b verts" "Voir docs/TODO.md."
iss "Remettre docs/TODO.md à jour" "P1,area:docs,owner:claude" "tableau d'état exact" "L'import YWH public n'est pas noté."
iss "Réévaluer la phase 2 (alias, calibrage, mineur)" "P1,area:tokens,owner:claude,research-check" \
  "décision écrite, chiffres de la mesure P0 à l'appui" "Les commandes pèsent peu face aux observations."
iss "Parallélisme dans le quota" "P2,area:autonomy,owner:claude,build" \
  "2 segments simultanés sans conflit de gate ni de board" "ARTEMIS : avantage de l'exploitation parallèle."
iss "Mode CVE : analyse de variantes de patchs récents" "P2,area:cve,owner:claude,build" \
  "un repo fixture -> finding dans le board" "CyberGym (arXiv:2506.02548) : 17-18 patchs incomplets trouvés."
iss "Connecteur Intigriti (H4)" "P2,area:scope,owner:hermes,build" "critères de docs/TODO.md" "Phase 3."
iss "Capture de session humaine via le gate (4.5)" "P2,area:gate,owner:claude,build" \
  "login manuel sur l'app de test -> requêtes agent authentifiées" "Phase 4."
iss "Comparer notre PoC triager au YWH Claude Kit" "P2,area:verify,owner:claude,research-check" "écarts listés" \
  "https://www.yeswehack.com/learn-bug-bounty/triager-grade-reports-claude-code"
