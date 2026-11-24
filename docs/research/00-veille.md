# Veille initiale — bull-harness (2026-11-22)

Statut : sources majoritairement secondaires. Chaque point marqué ⚠ doit être vérifié sur source primaire avant d'en dépendre.

## R1 — Économie de tokens

| Fait | Conséquence design | Source |
|---|---|---|
| Tokenizer Claude non public. `@anthropic-ai/tokenizer` = ancien (ère Claude 2). Claude ≥ 4.7 : nouveau tokenizer, ~+30 % tokens vs anciens. | Calibrer les alias **sur Claude**, pas sur cl100k/DeepSeek. Méthode : endpoint `count_tokens` (gratuit, clé API), mesure différentielle `count(prefix + sym) − count(prefix)`. | platform.claude.com/docs/build-with-claude/token-counting |
| L'agent exécute via `bash -c` : `~/.bash_history` ne voit pas ses commandes ; `alias` bash non expansé en non-interactif. | Watchdog = mineur sur **log de hook PreToolUse** + transcripts JSONL, pas bash_history. Alias = **wrappers exécutables** dans `$PATH` du conteneur. | skill token-efficient-agent-commands |
| PreToolUse peut réécrire la commande Bash (`hookSpecificOutput.updatedInput` + `permissionDecision`). | Le pattern rtk : wrapper la commande dans un filtre avant exécution. | code.claude.com/docs/en/hooks, rtk-ai/rtk |
| ⚠ PostToolUse `updatedToolOutput` pour tous les outils depuis v2.1.121 (avant : MCP seulement, `updatedMCPToolOutput`). | Deuxième point de troncature, après exécution. À vérifier sur la version installée. | claudeissues #54161 / #32105 |
| rtk (Rust Token Killer) : proxy CLI, 100+ commandes filtrées, sortie brute sauvée dans un fichier en cas d'échec, `rtk discover` mine les JSONL Claude Code. Concurrents : lean-ctx, lowfat, rskim, syntext. | Reprendre le pattern « sortie filtrée + pointeur vers le brut » pour nos builtins. Attention : homonyme `rtk` sur crates.io. | github.com/rtk-ai/rtk |

## R2 — Arsenal / sandbox Kali

- Image officielle `kalilinux/kali-rolling` (~46 Mo, **sans** métapaquet). `apt install kali-linux-headless` à faire dans le Dockerfile ; image résultante de l'ordre de 3 Go (build tiers, non vérifié).
- Projets de référence à disséquer : PentAGI (multi-agent, outils en conteneurs Docker isolés), Strix (Apache 2.0, web), CAI (Alias Robotics), Shannon (white-box), HexStrike AI (serveur MCP, 150+ outils), Xalgorix (vérificateur qui ré-exploite chaque finding).

## R3 — Scopes autonomes

- `arkadiyt/bounty-targets-data` : dumps horaires des scopes HackerOne/Bugcrowd/Intigriti/YesWeHack/… → source de diff pour détecter les évolutions de scope.
- HackerOne Hacker API : endpoint structured scopes (basic auth user+token), **50 req/min** depuis 2026-06-22, filtres par date de MAJ depuis 2026-01-15. ⚠ chemin exact à lire sur api.hackerone.com/hacker-reference.
- `sw33tlie/bbscope` : outil d'extraction de scopes multi-plateformes.
- Politique plateformes 2026 : Bugcrowd suspend 30 jours les comptes qui soumettent des rapports IA non validés ; HackerOne demande aux programmes de préciser s'ils autorisent les hackbots. → **vérificateur obligatoire** avant qu'un finding atteigne la todo humaine ; flag `automation_allowed` par programme dans le scope en dur.

## R4 — Notifications Gmail

- Gmail API → Cloud Pub/Sub : topic + droit de publication pour `gmail-api-push@system.gserviceaccount.com` + `users.watch`.
- `watch` à renouveler **au moins tous les 7 jours** ; `history.list` depuis le `historyId`.
- Abonnement Pub/Sub en **pull** possible → pas besoin d'exposer un endpoint HTTPS public.

## R5 — Auth Claude (abonnement vs API)

- ⚠ Fév 2026 : Anthropic interdit aux produits **tiers** d'utiliser l'OAuth des plans Free/Pro/Max.
- ⚠ 15 juin 2026 : changement suspendu — Agent SDK, `claude -p` et apps tierces puisent toujours dans les limites de l'abonnement.
- ⚠ 7 oct 2026 : Max/Team reçoivent des crédits API mensuels (Max 5x 100 $, Max 20x 200 $) utilisables par Agent SDK / `claude -p` / API **avec une clé API d'une org Console liée**. Connecté avec le plan : consomme les limites du plan, pas les crédits.
- Conception retenue : le harnais pilote le **CLI officiel `claude` en headless** (moteur interchangeable), auth = au choix connexion abonnement ou clé API Console. Aucun relais d'OAuth vers un tiers.

## CVP (Cyber Verification Program)

- Élargi le 2026-10-06 : trois tiers (Defense, Red Team, Specialized). Rétention de données obligatoire pour les orgs inscrites. Le tier Defense bloquerait encore la plupart des tâches offensives (critique tierce).
- ⚠ À vérifier : quel tier a Mio, et sur quelle surface (compte claude.ai / Claude Code / org API) il s'applique. Si le CVP est lié à une org API, le moteur doit utiliser cette org.

## Questions ouvertes
1. Tier CVP et surface couverte.
2. Plan Claude (Pro / Max 5x / Max 20x) → budget de concurrence d'agents.
3. Hôte : Docker ou Podman (Fedora 44) ? rootless ?
4. Plateformes visées en priorité (H1, Bugcrowd, Intigriti, YWH).
