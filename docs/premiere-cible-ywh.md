# Première cible YesWeHack : checklist

Chaque ligne est vérifiable. On ne lance `bh run` qu'une fois tout coché.

## 1. Choisir et importer le programme
- [ ] Programme **public**, scope web, comptes en auto-inscription (sinon pas de test authentifié).
- [ ] `uv run bh scope import ywh <slug> --username <ton pseudo YWH>` → `scopes/ywh/<slug>.yaml`.
      L'import ne fait jamais grandir le scope : ce qui ne s'exprime pas exactement est listé « NOT enforced ».
- [ ] Lire la page du programme en entier (lien dans `notes` du YAML), pas seulement les extraits affichés.

## 2. Régler le YAML (c'est toi qui décides, pas l'importeur)
- [ ] `automation_allowed: true|false` selon les règles. `null` bloque le runner.
- [ ] `scanners_allowed: true|false` selon les règles. `null` bloque le runner (l'import met déjà `false` quand il détecte une interdiction, mais il en rate : relire les règles).
      Effet : bh-content, bh-scan, bh-params, bh-sqli, bh-xss et nuclei/sqlmap/ffuf directs sont refusés ; seuls bh-recon, bh-crawl et le manuel restent.
- [ ] `user_agent` : comparer la valeur de l'API et celle du texte des règles ; garder celle que les règles exigent.
- [ ] `required_headers` : ajouter tout en-tête d'identification exigé.
- [ ] `max_rps` : la valeur des règles, sinon laisser vide (le gate applique 2 req/s et ralentit sur 429/503/WAF).
- [ ] Relire `out_of_scope` et les entrées « NOT enforced ».
- [ ] `uv run bh scope check scopes/ywh/<slug>.yaml <url hors scope> <url dans le scope>` : DENY / ALLOW attendus.

## 3. Comptes de test
- [ ] Créer **deux** comptes avec ton alias `@yeswehack.ninja` (secrets/researcher.env) : user-a, user-b.
- [ ] Les enregistrer comme identités : UI → Todo → « Enregistrer une identité », ou `var/state/identities/ywh-<slug>/<nom>.json`
      (`{"headers": {"Cookie": "...", "Authorization": "..."}}`, chmod 600). L'agent ne voit jamais ces valeurs.

## 4. Stack
- [ ] `uv run bh up` ; `podman exec -i --user hunter bh-agent bash -s < tests/escape/escape_check.sh` → `failures: 0`
      (la suite utilise le scope lab : la relancer avant d'activer le programme réel).
- [ ] Ta page d'usage claude.ai : assez de fenêtre restante pour le segment prévu.

## 5. Premier segment, court et suivi
- [ ] `uv run bh run scopes/ywh/<slug>.yaml --effort medium --minutes 20 --max-turns 30`, UI ouverte sur « Live ».
- [ ] Après le run : `uv run bh flows -n 200` et l'onglet Trafic : aucune requête hors scope, débit conforme, en-têtes présents.
- [ ] Tout finding est `new` : tu rejoues la PoC toi-même avant toute soumission (pas de vérificateur automatique pour l'instant).
