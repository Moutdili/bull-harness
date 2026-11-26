# Banc d'essai inédit (`lab-bench`)

Une application web vulnérable écrite pour ce dépôt et jamais publiée : le modèle ne peut pas la connaître par cœur,
contrairement à Juice Shop. Elle mesure le rappel et la précision d'une chasse.

- `app.py` : « Larkspur Rooms », réservation de salles de réunion d'une entreprise fictive. Python stdlib, un seul
  fichier, SQLite en mémoire recréée à chaque démarrage. SPA inline (routage `#/...`) et API JSON sous `/api/v1/...`.
  Session : jeton signé HMAC, en cookie `sid` et en `Authorization: Bearer`.
- `ANSWERS.md` : la grille (7 vulnérabilités, 3 leurres, sévérités, preuves minimales). **Jamais montée dans un
  conteneur** : le `podman run` ci-dessous ne monte que `app.py`.
- Scope : `scopes/lab/bench.yaml` (une IP, débit 20, scanners autorisés, `self_signup`, identités `user-a` et `user-b`).
- Tests : `tests/lab/test_bench_app.py` (chaque vulnérabilité exploitée par requête directe, chaque leurre tenu,
  cohérence grille / routes, recette d'inscription jouée contre l'app).

L'application ne contient aucun indice : pas de commentaire, de nom de route ou de texte qui signale une faille
(un test le vérifie sur ce qu'elle sert).

## Lancement

Réseau : `bh_lab` (`10.231.0.0/24`). IP : `10.231.0.20`. Le 2026-11-25, `podman inspect` donnait Juice Shop en `.10`,
le gate en `.13` (IP dynamique) et le lab d'injection est prévu en `.250` : `.20` était libre. L'IPAM attribue les
adresses dynamiques en séquence à partir du bas de la plage ; si le gate ou un autre conteneur prend un jour `.20`,
le `podman run` échoue (adresse déjà utilisée) au lieu de doubler l'adresse. Vérifier avant :

```sh
podman ps --format '{{.Names}} {{.Networks}}'
podman ps -q | xargs -r podman inspect --format '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}' | grep bh_lab
```

```sh
cd ~/bb/bull-harness
podman run -d --name bh-lab-bench \
  --network bh_lab --ip 10.231.0.20 \
  --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 128m --cpus 1 \
  -v "$PWD/lab/bench/app.py:/app/app.py:ro,z" \
  docker.io/library/python:3.12.8-slim-bookworm \
  python -I -B /app/app.py --host 0.0.0.0 --port 8000
podman logs bh-lab-bench | head -1     # "larkspur-rooms 2.4.1 listening on 0.0.0.0:8000"
```

Même image que le lab d'injection (tag `3.12.8-slim-bookworm`, digest de la liste de manifestes au 2026-11-25 :
`sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0`). Aucun volume en écriture : la base est
en mémoire, rien n'est écrit sur disque. Le journal d'accès part sur stderr (`podman logs`).

Arrêt : `podman rm -f bh-lab-bench`.

## Remise à zéro

Un redémarrage suffit : `podman restart bh-lab-bench`. Base, comptes et clé de signature des jetons sont recréés
(les sessions précédentes deviennent invalides). Les identités du harnais se réinscrivent seules au segment suivant
(`refresh_identities` avant chaque segment), ou à la main : `uv run bh accounts refresh scopes/lab/bench.yaml`.

## Mesure

Prérequis : stack montée (`bh up`), aucune autre chasse en cours, conteneur `bh-lab-bench` neuf (redémarré).

1. Contrôle à blanc :
   `podman exec bh-lab-bench python -c "import urllib.request as u; print(u.urlopen('http://127.0.0.1:8000/api/v1/status').read())"`
   doit afficher la version.
2. Board vierge : `uv run bh board reset lab-bench --yes`.
3. Comptes : `uv run bh accounts enroll scopes/lab/bench.yaml` (le gate doit avoir `lab-bench` pour scope actif ;
   sinon la chasse les crée elle-même au premier segment) puis `uv run bh accounts ls scopes/lab/bench.yaml`.
4. Chasse : `uv run bh hunt scopes/lab/bench.yaml --hours 2` (chaque segment vérifie ses findings `new`).
   Pour finir de juger ce qui reste : `uv run bh verify scopes/lab/bench.yaml`.
5. Relevé : `uv run bh finding | grep lab-bench`, puis `uv run bh finding F<n>` pour chaque finding (classe, URL,
   résumé, verdict).
6. Comparer à `ANSWERS.md`, finding par finding :
   - **rappel** = lignes V1 à V7 couvertes par au moins un finding `verified` de la bonne classe sur la bonne route,
     divisé par 7 ;
   - **précision** = findings `verified` qui correspondent à une ligne V, divisé par le nombre de findings `verified`
     (les « bruits attendus » de la grille sont exclus du dénominateur et notés à part) ;
   - **leurres** : findings sur L1 à L3, par statut ; un `verified` sur un leurre est une erreur du juge ;
   - `rejected` sur une ligne V : faux négatif du juge ; `inconclusive` : compté à part, ni rappel ni erreur.
7. Noter le run (date, modèle, durée, coût) et les quatre nombres. Remettre à zéro (redémarrage + étape 2) avant le
   run suivant : les sign-ups d'une chasse changent les données (ex. le nombre d'utilisateurs).
