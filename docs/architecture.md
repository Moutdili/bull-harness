# bull-harness — architecture v0 (2026-11-22)

Statut : **proposition, à valider par Mio**. Les points ⚠ restent à vérifier avant d'écrire le code qui en dépend.

## Contraintes fixées

| Contrainte | Valeur | Conséquence |
|---|---|---|
| CVP | tier **Defense** (individuel) | Source primaire : Defense est le tier prévu pour les bug bounty hunters, et couvre le triage et la validation de vulnérabilités. L'exploit dev et les outils offensifs relèvent de Red Team, **réservé aux organisations sur API/Enterprise**. Les refus restent possibles (faux positifs) : refus → fait `blocker`, pause 6 h, puis programme parqué (jamais de reformulation). Voir `cvp-red-team-dossier.md`. |
| Plan Claude | **Pro** | Fenêtre glissante de 5 h + plafond hebdo, partagés avec claude.ai. Pas de crédits API. → **1 agent à la fois**, superviseur qui dort jusqu'au reset, économie de tokens prioritaire. ⚠ Accès Opus sur Pro non confirmé : modèle configurable. |
| Conteneurs | **Podman 5.8.9 rootless** + podman-compose 1.6.0 | Pas de socket root à monter, ce qui évite la classe de CVE-2026-14784. Le compose doit rester compatible docker compose. ⚠ Vérifier `internal: true` sous podman-compose. |
| Plateformes | **YesWeHack, Intigriti** puis H1/Bugcrowd | Règles par programme : en-tête obligatoire (`X-Intigriti-Username`, `User-Agent: Intigriti-<user>`, `Infomaniak-YWH-Bugbounty`…) et plafond de requêtes (3 à 20 req/s selon le programme). |
| Claude Code | 2.1.330 | Supérieur à 2.1.121 : `updatedToolOutput` en PostToolUse doit être disponible pour tous les outils. ⚠ À tester. |

## Vue d'ensemble

```
 hôte Fedora (Mio / Claude orchestrateur)
 ├─ bh (CLI)  ─────────────┐
 ├─ ui (web, SSE)          │  SQLite board : facts (+ blockers) / intents / findings / todos submit
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
 ┌─────────────────────────────────────┐
 │  judge (même image, même gate)      │ ← vérificateur : son /work (var/judge),
 │   · bh-agent replay + claude -p     │   ses process, son /tmp, user `judge`
 └─────────────────────────────────────┘
```

## Composants

### 1. `scope/` — scope en dur (cœur sécurité)
- Un fichier YAML par programme : `scopes/<platform>/<slug>.yaml`.
- Champs : `in_scope[]` (hôtes, wildcards, CIDR, apps), `out_of_scope[]`, `required_headers{}`, `user_agent`, `max_rps`, `automation_allowed`, `forbidden_vulns[]`, `identities[]` (références vers des secrets, jamais les secrets eux-mêmes), `source`, `synced_at`, `hash`.
- `enforce(url|host|ip) → allow|deny + raison` : **une seule fonction**, utilisée par le proxy, les builtins et `bh`. Un out-of-scope l'emporte toujours sur un in-scope.
- Un actif découvert hors scope est consigné (fait `out-of-scope`, un par run), **jamais** ajouté au scope ni ciblé.
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

### 5. `agent/` — arsenal (builtins) et verrou d'outils
Code du sandbox, stdlib seule, monté en lecture seule dans l'agent (`src/bh/agent`). Un seul exécutable
`bh-agent`, des liens `bh-recon`, `bh-crawl`, `bh-content`, `bh-scan`, `bh-params`, `bh-sqli`, `bh-xss`, `bh-note`.
- Chaque builtin : passe par le gate au débit du programme, `--as <identité>`, brut dans `raw/`, résumé ≤ 25 lignes,
  couverture enregistrée dans `coverage.json`, endpoints dans `endpoints.jsonl`.
- `bh-crawl` = katana + extracteur maison des chemins cités dans le JS/HTML (avec le verbe HTTP quand il est visible).
- **Verrou** (hook PreToolUse) : `curl`/`wget`/`python`… vers une origine sont refusés tant que crawl, content et scan
  n'y ont pas tourné. Le message `[bh-lock]` donne les commandes exactes.
- **File de surface** : le runner ajoute au board les endpoints trouvés et pas encore testés (testé = touché par un
  `curl` autorisé ou un builtin de test).
- Métrique par run : commandes arsenal / manuelles / verrouillées (`runs.arsenal_calls` …).

### 6. `runner/` — superviseur autonome
- Une boucle : choisir un programme (priorité, temps déjà passé, dernier progrès) → lancer `claude -p` avec le contexte du board → suivre le flux `stream-json`.
- **Rotation** si : aucun nouveau fait depuis N tours, durée T dépassée, budget de tokens épuisé, ou refus répétés.
- **Limite Pro atteinte** : sauvegarde de la session, sommeil jusqu'au reset, reprise.
- Reflector : message système explicite (« pas d'appel d'outil depuis N tours : choisis une intention du board ou rends la main »), jamais dans la voix de l'utilisateur.

### 7. `verify/` — vérificateur
Contexte neuf, il ne reçoit que la PoC. Il rejoue via le gate. Un finding non reproduit n'atteint pas la todo `submit`.
Il tourne dans le conteneur `bh-judge` (service compose `judge`, démarré par `bh up`) : même image et même gate que
l'agent, mais son propre `/work` (`var/judge` sur l'hôte), qui ne voit pas celui du chasseur (`var/work`). L'hôte y
pousse la preuve et le prompt (`stack.push_file(..., container=JUDGE_CTR)`) et relit le verdict dans `var/judge`.
Juge arrêté : la vérification est remise à plus tard (statut `new` inchangé, aucune erreur comptée).

### 8. Pas d'humain pendant la chasse (2026-11-25)
Mio n'intervient qu'**après le triage**, pour soumettre. Pendant un run, aucun composant n'attend un humain.
Détail et audit : `research/11-autonomie-sans-humain.md`.

Todo humaine (post-triage) :
| Type | Déclencheur | Action humaine |
|---|---|---|
| `submit` | finding vérifié par le juge (Opus, ou Mythos en escalade) | Relire la PoC, soumettre |

Blocages pendant la chasse : fait `blocker` (`[raison] quoi`, montré 7 jours dans la frontière, `bh blockers`, onglet « Pistes bloquées ») :
| Blocage | Traitement autonome |
|---|---|
| challenge WAF répété | le gate met l'hôte en pause 1 h (3 challenges en 10 min, règle `waf-cooldown`) ; ses endpoints sortent de la surface non testée |
| session expirée (401 répétés sous identité) | identité marquée périmée, retirée du prompt et du juge jusqu'à réécriture de son fichier ; relance du login par l'hôte (à venir, issue 26) |
| mur de login sans identité, 2ᵉ compte manquant | blocker `auth` / `account` ; comptes créés par l'hôte (à venir, issue 25) |
| captcha, SMS, KYC, fonction payante, écriture sur un tiers, hors bande | blocker `captcha` / `sms` / `kyc` / `paid` / `write-needed` / `oob-needed` ; jamais de résolution de captcha |
| actif hors scope | fait `out-of-scope` ; jamais d'élargissement |
| refus du modèle | blocker `refusal` ; 1ᵉʳ refus : pause 6 h ; 2ᵉ dans la chasse : programme parqué ; 3 en 7 jours : exclu au préflight |
| programme non prêt (`automation_allowed`, `scanners_allowed` inconnus) | exclu au préflight ; l'onboarding reste humain, hors chasse (autorisation légale) |
| juge `inconclusive` | escalade unique vers Mythos ; s'il reste `inconclusive`, statut visible dans Findings, sans todo |

### 9. `notify/`
Abandonné le 2026-11-25 (Gmail / Pub/Sub). La mise à jour des scopes sera déclenchée par un hook d'un autre type, le moment venu.

### 10. `ui/`
Vue en direct du flux de l'agent, board, findings + PoC (requêtes HAR rejouables en `curl`), todo de soumission, pistes bloquées, identités. Écoute sur l'IP Tailscale (ou `127.0.0.1`), jamais `0.0.0.0` ; connexion par token (`secrets/ui.token`) puis cookie HttpOnly ; CSP stricte, rendu `textContent` uniquement.

### 11. `bh` — CLI orchestrateur
`bh scope add|sync|diff|check <url>` · `bh run [--program X] [--once]` · `bh todo [done <id>]` (soumissions) · `bh blockers [programme] [--since H]` · `bh finding ls|show|verify` · `bh target local <url>` (cible perso : scope généré, en-têtes vides, débit libre) · `bh tokens calibrate|mine` (veille, alias abandonnés) · `bh ui`.
C'est l'interface par laquelle Claude (cette session) pilote le harnais.

## Stack
Python 3.12 + `uv` (mitmproxy et les hooks sont en Python ; un seul langage). SQLite pour le board : un agent à la fois, pas besoin de Postgres.

## Risques
1. Tier Defense : refus sur l'exploitation. Mitigation : refus → blocker, abandon chiffré, et dossier Red Team.
2. Quota : plan Ultra depuis le 2026-11-24 (plus de fenêtre de 5 h). Mitigation conservée : Sonnet chasse, Opus juge, mesure du coût par finding vérifié.
3. API YesWeHack non documentée : peut casser. Mitigation : fallback `bounty-targets-data` + édition manuelle du YAML.
4. Gate HTTP seulement contournable par un outil qui ignore le proxy. Mitigation : l'agent n'a **aucune route** hors du réseau `sandbox`. Le gate est le seul chemin, pas une convention.

## Limites connues (après les deux revues hostiles du 2026-11-24)
- **Proxy du gate ouvert à ses réseaux** : `regular@8080` accepte tout client des réseaux du gate, donc aussi Juice
  Shop sur le réseau `lab`. Sans effet sur une cible réelle, qui n'est jamais sur nos réseaux ; le relais Anthropic, lui,
  n'accepte que l'agent et le juge. L'enrôlement des comptes passe volontairement par ce proxy depuis le gate (`127.0.0.1:8080`)
  pour subir la même politique que l'agent.
- **Session morte** : un 401 sous identité peut être un refus d'accès légitime (objet d'un autre). La marque « périmée »
  qu'il pose est levée au segment suivant si la sonde de l'identité (`probe`, avec contenu attendu) répond bien.
- **MCP** : la session de l'agent et celle du juge ne chargent aucun serveur MCP (`--strict-mcp-config` sans
  `--mcp-config`), et un `.mcp.json` laissé dans le dossier de travail est effacé entre deux segments. Raison : les hooks
  ne voient que `Bash`. Les outils tiers entrent comme builtins `bh-*` (`research/08-mcp-arsenal.md`).
- **Jeton OAuth** : n'existe que dans le gate ; l'agent a un jeton factice et `ANTHROPIC_BASE_URL=http://gate:8081`.
  Le relais n'accepte que les conteneurs agent et juge (résolus par nom, `BH_AGENT_HOST` / `BH_JUDGE_HOST`, cache
  60 s, une relecture DNS au plus toutes les 5 s pour une IP refusée ; le gate est aussi sur le réseau du lab, qui
  reste refusé), que les deux appels que fait
  Claude Code (`POST /v1/messages`, `/v1/messages/count_tokens`, mesuré sur 2.1.330), seulement pendant un run, et
  au plus `3 × max_turns + 30` requêtes par segment. Reste : dans ce budget, un `claude -p` imbriqué consomme le
  quota (sans jeton à exfiltrer).
- **Le sandbox n'est pas une frontière** : hooks, verrou d'outils et fichiers du contrat sont des aides. Les garanties
  dures sont dans le gate (scope jugé sur le nom demandé, méthodes et overrides, identités existantes, ports web,
  énumération sur la route normalisée, garde scanners par rafale de 404, websockets refusés, débit) et sur l'hôte
  (ingestion typée, preuve revalidée, « testé » confirmé par le gate, secrets caviardés).
- **Exclusions** : une entrée YWH n'exclut une classe entière que si elle la nomme ; les exclusions conditionnelles
  restent à l'humain. Brute force interdit par la doctrine et, pour les programmes sans scanners, freiné par la garde
  404 du gate. Exclusions sans signature réseau (social engineering, physique) : doctrine seulement.
- **Vérificateur** : conteneur à lui (`bh-judge`, issue 3) : le chasseur ne voit ni son `/work`, ni ses process, ni
  son `/tmp`, et réciproquement ; même durcissement que l'agent, réseau `sandbox` seul, donc toujours derrière le gate
  (aucun nouveau chemin réseau). Dans ce conteneur : utilisateur Unix `judge`, tous ses process tués, HOME et
  fichiers temporaires effacés et dossier recréé avant chaque vérification ; `python3 -I`, modèle différent (Opus),
  verdict valable seulement avec le nonce donné au seul process du juge. Les process du chasseur sont encore tués
  avant le rejeu (pour l'état de la cible, plus pour l'isolation). Reste : le juge lit des réponses de la cible
  (injection de prompt possible, comme pour tout relecteur) ; il partage avec le chasseur l'image, le gate, le
  budget de relais du run et le code sandbox monté en lecture seule.
- **Énumération** : comptée sur le chemin, la query string, les corps formulaire et JSON et GraphQL (nom de
  paramètre qui désigne un id, valeur qui en a la forme). Un id sous un nom quelconque (`?q=123`) n'est pas compté.
- **Stockage** : fichiers de flux supprimés après 14 jours, journaux du gate tournés en gzip au-delà de 64 Mo
  (`bh prune`, et au début de chaque segment). Images épinglées par digest ; les paquets apt de Kali suivent le dépôt.
- **Coût du verrou sur une vraie cible** : crawl + content + scan par origine (~10 min chacun à 2 req/s).
- **nuclei** : ~1,5 req/s via le gate, cause interne non trouvée ; borné par `--timeout`.
- **Rechargement du gate** : mitmdump recharge `addon.py` mais pas `policy.py` ; après une modification de la
  politique, `podman restart bh-gate` (en attendant, le gate refuse : fail-closed).
- Liste à jour des points ouverts : `docs/TODO.md`, section « Revue hostile du 2026-11-24 ».
