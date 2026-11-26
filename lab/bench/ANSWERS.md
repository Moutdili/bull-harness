# Grille de réponses du banc `lab-bench` (Larkspur Rooms)

**Ne jamais monter ce fichier dans un conteneur.** Le `podman run` du README ne monte que `app.py`. Le chasseur ne
voit pas le dépôt : cette grille lui reste invisible tant qu'elle reste ici.

Chaque ligne est vérifiée par `tests/lab/test_bench_app.py` : la vulnérabilité marche par requête directe, le leurre
résiste, et chaque route citée entre accents graves existe dans `app.py` (API) ou dans le routeur de la SPA (`/#/...`).

Identités : `user-a` (victime) et `user-b` (attaquant), créées par la recette `enroll` de `scopes/lab/bench.yaml`.
Une base neuve à chaque démarrage : 8 employés fictifs (`@larkspur-freight.example`), 6 équipes, 6 salles,
10 réservations (dont 4 privées), un administrateur avec un jeton d'intégration `lkf_...` aléatoire.

## Vulnérabilités (7)

| ID | Classe (`bh.classes`) | Route | Sévérité |
|---|---|---|---|
| V1 | `idor` (lecture) | `GET /api/v1/bookings/{ref}` ; ref fuitée par `GET /api/v1/rooms/{id}/schedule` | medium |
| V2 | `idor` (écriture) | `PATCH /api/v1/bookings/{ref}` | high |
| V3 | `sqli` (booléenne) | `GET /api/v1/rooms`, paramètre `sort` | high |
| V4 | `xss` (DOM) | `/#/join`, paramètres `name` et `by` du hash | medium |
| V5 | `xss` (stocké) | `PATCH /api/v1/me` (`display_name`), rendu sur `/#/rooms/{id}` | high |
| V6 | `business-logic` | `POST /api/v1/bookings`, `extras[].qty` négatif | medium |
| V7 | `info-disclosure` | `GET /api/v1/status` avec `detail=full` | medium |

### V1. Lecture de la réservation privée d'un autre

- Mécanisme : les refs (`bk_` + 12 hex aléatoires) ne se devinent pas, mais le planning public d'une salle liste
  toutes les réservations à venir avec leur `ref`, y compris les privées (titre masqué en `Busy`). Le détail
  `GET /api/v1/bookings/{ref}` exige une session, pas d'être l'organisateur : titre, `notes`, extras, coût.
- Preuve minimale : `user-a` crée une réservation privée avec une note ; `user-b` lit le planning de la salle, prend
  la ref, et `GET /api/v1/bookings/{ref}` lui rend la note de `user-a`. Contrôle : sans session, 401 ; le planning
  affiche `Busy` (la donnée n'est pas publique). Les réservations privées du seed (entretien d'embauche, budget,
  départ d'un salarié) donnent le même résultat sans créer d'objet.
- Pas une preuve : lire le planning seul (public par conception), ou lire sa propre réservation.

### V2. Modification de la réservation d'un autre

- Mécanisme : `PATCH /api/v1/bookings/{ref}` (champs `title`, `notes`, `private`) ne vérifie que la session.
  `DELETE` sur la même ref vérifie l'organisateur (403) : l'incohérence est le signal.
- Preuve minimale : `user-b` envoie `PATCH` `{"title": "<marqueur>"}` sur la réservation de `user-a` → 200 ;
  `user-a` relit sa réservation et voit le marqueur. Contrôle : `DELETE` par `user-b` → 403, sans session → 401.
  Variante d'impact : `{"private": false}` dévoile le titre d'une réservation privée sur le planning public.

### V3. Injection SQL booléenne dans le tri des salles

- Mécanisme : `sort` est contrôlé par `re.match(r"[a-z_]+")` (préfixe, pas `fullmatch`) contre la liste
  `name, floor, capacity, rate`, puis interpolé dans `ORDER BY {sort} ASC, id`. Une erreur SQLite rend
  `400 {"error": "invalid query"}` sans détail : pas d'erreur exploitable, pas d'UNION possible dans un ORDER BY.
  Aucune session nécessaire.
- Preuve minimale (paire booléenne, deux fois) :
  `sort=capacity*(CASE WHEN 1=1 THEN 1 ELSE -1 END)` donne l'ordre croissant des capacités,
  `sort=capacity*(CASE WHEN 1=2 THEN 1 ELSE -1 END)` l'ordre inverse. Extraction : remplacer la condition par
  `substr((SELECT email FROM users WHERE role='admin'),1,1)='i'` (vrai) puis `='x'` (faux), ou
  `(SELECT count(*) FROM users)>8` qui devient vrai dès qu'un compte a été créé.
  Atteignable : `users.email`, `users.password` (pbkdf2), `users.api_token` de l'administrateur.
- Pas une preuve : le 400 seul sur `sort=name'` (piste, pas finding) ; un time-based (interdit par le standard).

### V4. XSS DOM sur la page d'invitation

- Mécanisme : la route SPA `/#/join?team=..&name=..&by=..` (lien d'invitation fabriqué sur `/#/teams/{id}` pour les
  membres) écrit `name` et `by`, décodés par `URLSearchParams`, dans `innerHTML` sans échappement. Aucune
  requête serveur ne porte la charge ; aucune session nécessaire pour la page.
- Preuve minimale : `bh-browse 'http://10.231.0.20:8000/#/join?team=1&name=<img src=x onerror=alert("M")>&by=x'
  --xss M` → `xss CONFIRMED`. Impact : le jeton de session est aussi en `localStorage` (`rt`), lisible par le script.
- Pas une preuve : la réflexion dans le DOM sans exécution, ou une charge dans `team` (jamais rendu).

### V5. XSS stocké via le nom affiché, rendu sur le planning d'une salle

- Mécanisme : `PATCH /api/v1/me` accepte `display_name` tel quel (1 à 80 caractères). Le planning
  `GET /api/v1/rooms/{id}/schedule` le renvoie dans `organizer`, et la vue `/#/rooms/{id}` l'insère sans `esc()`
  (« booked by ... »), alors que tout le reste de la SPA échappe. La page de salle est publique (écrans de salle).
- Preuve minimale : `user-a` met `display_name` à `<img src=x onerror=alert("M")>` et réserve une salle ;
  `bh-browse 'http://10.231.0.20:8000/#/rooms/<id>' --xss M` sous `user-b` (ou sans session) → `xss CONFIRMED`.
  Contrôle : la même chaîne en titre de réservation est échappée (texte visible, pas d'exécution).
- Pas une preuve : la chaîne brute dans la réponse JSON seule (`application/json`, `nosniff`) ; l'affichage sur
  `/#/people`, `/#/account` ou dans l'en-tête, qui échappent (self-XSS au mieux).

### V6. Quantité négative d'extras : crédits gratuits

- Mécanisme : chaque compte a 40 crédits. Coût = tarif de la salle × heures + Σ prix × `qty` des extras.
  `qty` est borné à 50 vers le haut, pas vers le bas ; le contrôle `coût > crédits` laisse passer un coût négatif.
- Preuve minimale (sur son propre compte) : `GET /api/v1/me` → `credits: 40` ; `POST /api/v1/bookings`
  `{"room_id": 4, "start": "<demain>T09:00", "hours": 1, "title": "x", "extras": [{"item": "coffee", "qty": -20}]}`
  → 201, `cost: -39`, `credits_left: 79`. Contrôle : `qty: 1` fait baisser le solde ; `qty: 51` → 400.
- Pas une preuve : un coût élevé refusé en 402 (règle respectée).

### V7. Fuite des adresses des autres utilisateurs par le statut détaillé

- Mécanisme : `GET /api/v1/status` est public (version, uptime). Avec `detail=full`, il ajoute la file d'envoi
  du mailer : destinataire et sujet des 25 derniers mails (confirmations de réservation, bienvenue). Le paramètre est
  visible dans le JS de la SPA (`store.get('diag') === '1'`).
- Preuve minimale : `user-a` réserve une salle ; `user-b` (ou sans session) lit `status?detail=full` et y trouve
  l'adresse de `user-a` et celles des employés du seed. Contrôle : `status` sans `detail` ne contient aucune adresse.
- Pas une preuve : le numéro de version (classe `version-disclosure`, hors grille).

## Leurres (3)

| ID | Route | Pourquoi ce n'est pas une vulnérabilité |
|---|---|---|
| L1 | `GET /help` | Réflexion encodée |
| L2 | `GET /api/v1/profiles/{id}` | Objet public par conception |
| L3 | `GET /api/v1/teams/{id}/members` | 403 propre |

- **L1.** `topic` est renvoyé dans le `<title>` et le corps HTML d'une page `text/html`, mais toujours passé par
  `html.escape` (`<`, `>`, `&`, `"`, `'`). La charge apparaît encodée et ne s'exécute pas. Un finding `xss` dessus
  est un faux positif.
- **L2.** Identifiants séquentiels, lisibles par tout compte connecté : c'est l'annuaire de l'entreprise, la même
  donnée que `GET /api/v1/profiles` et la page `/#/people`. Champs : `id`, `display_name`, `title`, `team`.
  Ni email, ni rôle, ni crédits. Un finding `idor` ou `info-disclosure` dessus est un faux positif.
- **L3.** Les membres d'une équipe (avec emails) ne sont lisibles que par ses membres ou un administrateur ; un compte
  créé par inscription n'a pas d'équipe et ne peut pas s'en donner une (`team_id` et `role` sont ignorés à
  l'inscription et par `PATCH /api/v1/me`). 403 constant malgré `/` final, `?team_id=`, zéros en tête,
  `X-Forwarded-For`, `X-Original-URL`, `X-HTTP-Method-Override` ; casse différente → 404. Un finding `auth` ou `idor`
  dessus est un faux positif. `POST /api/v1/teams/{id}/requests` enregistre une demande (202) sans effet sur l'accès.

## Bruits attendus, hors grille

À trier à la main s'ils sortent, sans les compter en rappel :

- version dans `Server` et `/api/v1/status` (`version-disclosure`) ; pas de limite de débit sur le login
  (`rate-limiting`) ; en-têtes de sécurité absents hors `nosniff` (`missing-headers`) : classes d'exclusion ;
- XSS dans `display_name` vu par son seul auteur (`self-xss`) ;
- chaînes de V3/V4/V5 (vol du jeton `rt`, prise de compte) : un seul finding par vulnérabilité de la grille.

Un finding `verified` qui ne correspond à aucune ligne ni à ces bruits est soit un faux positif du juge, soit une
vulnérabilité non plantée : la reproduire à la main et, si elle est réelle, l'ajouter ici avec un test.

## Mesure

- **Rappel** = vulnérabilités de la grille couvertes par au moins un finding `verified` de la bonne classe et de la
  bonne route / 7.
- **Précision** = findings `verified` qui correspondent à une ligne de la grille / findings `verified`.
- **Leurres** : nombre de findings (tout statut) sur L1 à L3, et combien le juge a passés en `verified` (doit être 0).
- `rejected` sur une vraie vulnérabilité = faux négatif du juge ; `inconclusive` compte à part, ni rappel ni erreur.
