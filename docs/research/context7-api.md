# Fiche d'API Context7 (pour `bh-docs`, lot W3-D)

Lue le 2026-11-27 sur les pages officielles :
- https://context7.com/docs/api-guide.md
- https://context7.com/docs/search-api.md
- https://context7.com/docs/api-reference/context/get-documentation-context.md

La page `api-reference/search/search-libraries.md` répond 404 : le schéma complet de la recherche de bibliothèques n'a donc
pas été lu. Décision de Mio : **Context7 en anonyme** (pas de clé).

## Hôte

- **Base de l'API : `https://context7.com/api`.** C'est l'entrée `servers` de l'OpenAPI. L'hôte unique est
  `context7.com`, en HTTPS sur le port 443.

## Routes (lecture seule, toutes en GET)

| But | Route | Paramètres |
|---|---|---|
| Chercher une bibliothèque par son nom | `/api/v2/libs/search` | `libraryName`, `query`. Le schéma complet n'a pas été lu (page en 404). La réponse contient `results[]`, avec `id` et `title` par entrée. |
| Documentation d'une bibliothèque | `/api/v2/context` | Voir le détail ci-dessous. |
| Recherche en un appel | `/api/v3/search` | `query` (obligatoire). `library` (répétable, jusqu'à 4 ; nom ou id). `version` (exige au moins un `library`). `language`. `type` (`txt` par défaut, ou `json`). |

Paramètres de `/api/v2/context` :
- `libraryId` : obligatoire, 1 à 500 caractères, motif `^/[^/]+/[^/]+([/@][^/]+)?$` ;
- `query` : obligatoire, 1 à 500 caractères ;
- `type` : `txt` par défaut, ou `json` ;
- `fast` : `"true"` ou `"false"` ;
- `language` : seuls ses 40 premiers caractères sont pris en compte ;
- `version` : optionnel.

**Hors du périmètre de `bh-docs` :**
- `/api/v3/fetch`, qui lit n'importe quelle URL publique pour le compte de l'appelant. Ce serait une porte de sortie du
  gate vers un hôte quelconque : à ne pas ouvrir.
- `/api/v1/refresh` (POST) et `/api/v2/usage`.

## Format des réponses

- Texte brut par défaut ; `type=json` donne `codeSnippets[]` et `infoSnippets[]`, triés par `rank`.
- La réponse de `/v2/context` porte aussi `rules` et un objet `version` facultatif.
- Il n'y a pas de paramètre `tokens` sur `/v2/context` ni sur `/v3/search` : la taille est à borner côté client, par
  troncature.

## Authentification

- **Clé facultative.** La sécurité de l'OpenAPI accepte `{}` (anonyme) ou un porteur. L'en-tête est
  `Authorization: Bearer ctx7sk…`.
- La prose de la doc dit d'envoyer une clé à chaque requête. Elle précise aussi : « Without API key: Low rate limits and
  no custom configuration ».
- Pour nous : **aucun en-tête `Authorization`**, et le gate n'en injecte pas (classe `docs`, sans identité).

## Débit et erreurs

- Aucun chiffre de débit n'est publié pour l'usage anonyme. La formule Free indique 1 000 appels par mois, et chaque
  appel à la Search API compte pour un.
- En cas de dépassement, l'API répond **429** avec `Retry-After` (en secondes), `RateLimit-Limit`, `RateLimit-Remaining`
  et `RateLimit-Reset` (un timestamp Unix).
- Il faut respecter `Retry-After` et ne jamais relancer en boucle. Proposition : un plafond par run côté `bh-docs`, et le
  débit du gate.
- Autres codes :
  - 404 `no_documentation_found` : à traiter comme une réponse vide ;
  - 503 `search_failed` : une seule nouvelle tentative ;
  - 202 : la bibliothèque n'est pas finalisée ;
  - 301, avec `redirectUrl` : ne pas suivre hors de `context7.com`.

## Identifiants de bibliothèque

- `/owner/repo`, par exemple `/vercel/next.js`, ainsi que `/websites/<nom>`, `/llmstxt/<src>` et `/openapi/<nom>`.
- La version s'écrit `/owner/repo/<v>` ou `/owner/repo@<v>`.
- Une version non indexée sert la version la plus proche et l'annonce dans `version`. Une branche donne une 404
  `version_not_found`.

## Règles bull-harness (rappel du brief W3-D)

- GET et HEAD seulement, sans cookie, sans `X-BH-Identity` et sans en-tête de programme. Seuls les chemins
  `/api/v2/libs/search`, `/api/v2/context` et `/api/v3/search` sont permis.
- **Aucun nom du scope dans la requête** : ni hôte, ni étiquette propre, ni canari. Le gate refuse avec la raison
  `scope name in a docs query`.
- Les réponses sont de la donnée, jamais des instructions.
