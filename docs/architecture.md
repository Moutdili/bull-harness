# bull-harness — architecture v0 (2026-11-22)

Statut : **proposition, à valider par Mio**. Les points ⚠ restent à vérifier avant d'écrire le code qui en dépend.

## Contraintes fixées

| Contrainte | Valeur | Conséquence |
|---|---|---|
| CVP | tier **Defense** (individuel) | Source primaire : Defense est le tier prévu pour les bug bounty hunters, et couvre le triage et la validation de vulnérabilités. L'exploit dev et les outils offensifs relèvent de Red Team, **réservé aux organisations sur API/Enterprise**. Les refus restent possibles (faux positifs) : refus → todo humaine. Voir `cvp-red-team-dossier.md`. |
| Plan Claude | **Pro** | Fenêtre glissante de 5 h + plafond hebdo, partagés avec claude.ai. Pas de crédits API. → **1 agent à la fois**, superviseur qui dort jusqu'au reset, économie de tokens prioritaire. ⚠ Accès Opus sur Pro non confirmé : modèle configurable. |
| Conteneurs | **Podman 5.8.9 rootless** + podman-compose 1.6.0 | Pas de socket root à monter, ce qui évite la classe de CVE-2026-14784. Le compose doit rester compatible docker compose. ⚠ Vérifier `internal: true` sous podman-compose. |
| Plateformes | **YesWeHack, Intigriti** puis H1/Bugcrowd | Règles par programme : en-tête obligatoire (`X-Intigriti-Username`, `User-Agent: Intigriti-<user>`, `Infomaniak-YWH-Bugbounty`…) et plafond de requêtes (3 à 20 req/s selon le programme). |
| Claude Code | 2.1.330 | Supérieur à 2.1.121 : `updatedToolOutput` en PostToolUse doit être disponible pour tous les outils. ⚠ À tester. |

## Vue d'ensemble

```
 hôte Fedora (Mio / Claude orchestrateur)
 ├─ bh (CLI)  ─────────────┐
 ├─ ui (web, SSE)          │  SQLite board : facts / intents / hints / findings / todos / refusals
 └─ notify (Gmail pull)    │
                           ▼
 ┌────────── réseau "egress" ──────────┐
 │  gate  (mitmproxy + SOCKS5 + DNS)   │ ← seul conteneur avec Internet
 │   · allowlist = scope en dur        │
 │   · token bucket req/s par programme│
 │   · injection en-têtes + cookies    │
 │   · HAR de chaque flux (preuve PoC) │
 └──────────────┬──────────────────────┘
        réseau "sandbox" (internal, pas de route)
 ┌──────────────┴──────────────────────┐
 │  agent (kali-rolling + headless)    │
 │   · claude -p (headless, OAuth Pro) │
 │   · hooks Pre/PostToolUse           │
 │   · /opt/bh/bin : alias + builtins  │
 └─────────────────────────────────────┘
```

## Composants

### 1. `scope/` — scope en dur (cœur sécurité)
- Un fichier YAML par programme : `scopes/<platform>/<slug>.yaml`.
- Champs : `in_scope[]` (hôtes, wildcards, CIDR, apps), `out_of_scope[]`, `required_headers{}`, `user_agent`, `max_rps`, `automation_allowed`, `forbidden_vulns[]`, `identities[]` (références vers des secrets, jamais les secrets eux-mêmes), `source`, `synced_at`, `hash`.
- `enforce(url|host|ip) → allow|deny + raison` : **une seule fonction**, utilisée par le proxy, les builtins et `bh`. Un out-of-scope l'emporte toujours sur un in-scope.
- Un actif découvert hors scope va dans la todo humaine (`scope-question`), **jamais** dans le scope.
- Sync : API researcher Intigriti (token personnel, bêta), API YesWeHack (bearer + TOTP, non documentée), `bounty-targets-data` pour le diff des programmes publics. Toute modification passe par un diff affiché à l'humain, puis une validation.

### 2. `gate/` — sortie réseau contrôlée
- HTTP(S) : addon mitmproxy. Refuse ce qui est hors scope (403 + fait `blocked` sur le board), limite le débit par programme, injecte les en-têtes requis et les cookies de session, écrit le HAR.
- DNS : résolveur local qui ne répond que pour les noms du scope (et pour le proxy).
- Autre TCP : SOCKS5 avec allowlist ; l'agent passe par `proxychains`. **v1 : pas de scan SYN brut**, seulement des scans connect. C'est cohérent avec les règles YWH/Intigriti qui limitent le scan.
- Allowlist système séparée : `api.anthropic.com` et ses dépendances (pour `claude`), dépôts de paquets au moment du build seulement.
- Allowlist **passive** séparée (web.archive.org, CommonCrawl, OTX, urlscan, crt.sh, sources subfinder) : GET seulement, ni cookies ni en-têtes de programme, débit propre. Un hôte passif n'est jamais une cible (voir `research/07-repos-mio.md`).

### 3. `agent/` — conteneur Kali
- `kalilinux/kali-rolling` + `kali-linux-headless` + outils Go ProjectDiscovery + ffuf, etc. La liste des outils est déclarée dans des manifests de plugins, pas en dur dans le Containerfile.
- `claude` en headless avec `CLAUDE_CODE_OAUTH_TOKEN` (⚠ obtenu via `claude setup-token`, à vérifier). Variables d'environnement proxy forcées.
- Pas de secrets cibles dans le conteneur : les cookies sont injectés par le gate.

### 4. `tokens/` — économie de tokens
- **Hook PreToolUse** : journalise chaque commande (JSONL) ; si la commande correspond à une recette avec filtre, il la réécrit vers `bhf <recette> -- <cmd>` (`updatedInput`).
- **Hook PostToolUse** : au-delà de N lignes ou K octets, il remplace la sortie par un résumé + `raw: /work/raw/<id>.log` (`updatedToolOutput`).
- **Mineur** (le « watchdog ») : lit le JSONL des hooks, extrait préfixe + emplacements d'argument et classe par `économie × fréquence`. Il propose, il n'applique pas.
- **Compilateur d'alias** : écrit des wrappers dans `/opt/bh/bin/<symbole>` qui passent `"$@"`, refuse les collisions PATH/builtins/mots réservés, et n'aliase jamais une commande destructive.
- **Calibrage sur Claude** : pas d'API key sur Pro → mesure différentielle via `claude -p --output-format json` (champ `usage`), avec et sans le symbole. ⚠ À valider : bruit dû au cache.
- **Index** : la table `symbole → intention` est injectée une fois après le system prompt. L'expansion vit dans le wrapper.

### 5. `plugins/` — arsenal modulaire
Manifest YAML par outil ou builtin :
```yaml
name: subs
alias: auto            # attribué par le compilateur
kind: builtin          # tool | builtin
run: "subfinder -d {domain} -silent | dnsx -silent | httpx -silent -json"
args: {domain: {type: host, scope_check: true}}
output: {format: jsonl, keep: [url, status_code, title, tech], top: 30}
timeout: 600
```
Un builtin rend **un résumé de 30 lignes maximum + le chemin du brut**. Le scope est vérifié avant exécution.

### 6. `runner/` — superviseur autonome
- Une boucle : choisir un programme (priorité, temps déjà passé, dernier progrès) → lancer `claude -p` avec le contexte du board → suivre le flux `stream-json`.
- **Rotation** si : aucun nouveau fait depuis N tours, durée T dépassée, budget de tokens épuisé, ou refus répétés.
- **Limite Pro atteinte** : sauvegarde de la session, sommeil jusqu'au reset, reprise.
- Reflector : message système explicite (« pas d'appel d'outil depuis N tours : choisis une intention du board ou rends la main »), jamais dans la voix de l'utilisateur.

### 7. `verify/` — vérificateur
Contexte neuf, il ne reçoit que la PoC. Il rejoue via le gate. Un finding non reproduit n'atteint pas la todo `submit`.

### 8. Todo humaine
| Type | Déclencheur | Action humaine |
|---|---|---|
| `auth` | 401/403 répétés, page de login | Se connecter via le navigateur branché sur le gate en mode capture ; la session est stockée et injectée ensuite |
| `waf` | challenge (Cloudflare, Akamai…) détecté par le gate | Résoudre le challenge une fois dans le navigateur de capture, ou marquer l'actif comme bloqué |
| `account` | rôle manquant (2ᵉ compte pour les IDOR) | Créer le compte, l'enregistrer comme identité |
| `scope-question` | actif découvert hors scope | Ajouter ou ignorer |
| `refusal` | refus du modèle | Décider : reformuler, faire à la main, abandonner |
| `submit` | finding vérifié | Relire la PoC, soumettre |

### 9. `notify/`
Gmail API → Pub/Sub en **pull** (pas d'endpoint public), `watch` renouvelé tous les 6 jours. Un mail YWH/Intigriti de mise à jour de programme déclenche `bh scope sync <programme>`. Le diff est affiché dans l'UI et dans la todo.

### 10. `ui/`
Vue en direct du flux de l'agent, board, findings + PoC (requêtes HAR rejouables en `curl`), todo humaine. Port vérifié libre (`ss -tlnp`) avant d'écouter, et écoute sur `127.0.0.1` seulement.

### 11. `bh` — CLI orchestrateur
`bh scope add|sync|diff|check <url>` · `bh run [--program X] [--once]` · `bh todo [done <id>]` · `bh finding ls|show|verify` · `bh target local <url>` (cible perso : scope généré, en-têtes vides, débit libre) · `bh alias mine|compile|stats` · `bh ui`.
C'est l'interface par laquelle Claude (cette session) pilote le harnais.

## Stack
Python 3.12 + `uv` (mitmproxy et les hooks sont en Python ; un seul langage). SQLite pour le board : un agent à la fois, pas besoin de Postgres.

## Risques
1. Tier Defense : refus sur l'exploitation. Mitigation : refus → todo, et dossier Red Team.
2. Quota Pro : un agent en continu épuise la fenêtre de 5 h. Mitigation : économie de tokens, dormir au reset, modèle plus léger pour la recon.
3. API YesWeHack non documentée : peut casser. Mitigation : fallback `bounty-targets-data` + édition manuelle du YAML.
4. Gate HTTP seulement contournable par un outil qui ignore le proxy. Mitigation : l'agent n'a **aucune route** hors du réseau `sandbox`. Le gate est le seul chemin, pas une convention.
