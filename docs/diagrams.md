# Diagrammes d'architecture

État du 2026-11-24, après la revue hostile (Mythos 5.2) et ses correctifs. Chaque bloc est du mermaid
rendu par GitHub. La dernière partie compare bull-harness aux outils étudiés avant de le construire.

## 1. Runtime · qui parle à qui

```mermaid
flowchart LR
  MIO(["Mio"]) --> UI
  MIO --> CLI
  subgraph HOST["Hôte · podman rootless"]
    CLI["bh CLI"] --> RUN["runner · un segment"]
    SUP["supervisor · hunt"] --> RUN
    RUN --> VER["verify · deux étages"]
    UI["ui · session HMAC"]
    BOARD[("board.sqlite<br/>runs · facts · findings<br/>todos · assets · métriques")]
    STATE[("var/state<br/>scope actif · run actif<br/>flows · events · identités")]
    RUN --> BOARD
    VER --> BOARD
    UI --> BOARD
  end
  subgraph AGENT["Conteneur agent · Kali · réseau sandbox"]
    CC["claude -p<br/>hooks PreToolUse / PostToolUse"]
    BI["builtins bh-recon · crawl · content<br/>scan · params · sqli · xss"]
    NOTE["bh-note · proof.json"]
    CC --> BI
    CC --> NOTE
  end
  subgraph GATE["Conteneur gate · mitmproxy · seul sur egress"]
    POL["policy · scope · méthodes<br/>ports · ids · débit · scanners"]
    REL["relais :8081<br/>jeton OAuth, agent seul"]
  end
  RUN -- "podman exec" --> CC
  CC -- "proxy :8080" --> POL
  BI -- "proxy :8080" --> POL
  CC -- "API Claude" --> REL
  POL --> TGT(["cibles in-scope"])
  POL --> PAS(["sources passives<br/>GET seulement"])
  POL --> LAB(["lab Juice Shop"])
  REL --> ANT(["api.anthropic.com"])
  POL -. "flows, events" .-> STATE
  STATE -. "curseurs" .-> RUN
  NOTE -. "/work/‹programme›" .-> RUN
  style POL stroke-width:4px
  style REL stroke-width:3px
```

## 2. Un segment · séquence

```mermaid
sequenceDiagram
  autonumber
  participant R as runner
  participant A as agent (claude -p)
  participant H as hooks
  participant G as gate
  participant B as board
  R->>R: verrou var/run.lock · règles humaines tranchées ?
  R->>A: reset utilisateur agent · HOME neuf · /work des autres fermé
  R->>G: scope actif + run actif (tag des flux)
  R->>A: doctrine + fiches de méthode (surface du board)
  loop jusqu'à 3 relances
    A->>H: commande Bash
    H-->>A: refus si verrou d'outils ou règle programme
    A->>G: requêtes HTTP(S)
    G-->>A: réponse ou 403 X-BH-Gate
  end
  A->>R: fin de session (stream-json, tokens, outils)
  R->>B: ingestion notes (types vérifiés, preuve revalidée, secrets caviardés)
  R->>B: graphe d'assets (curseur sur flows) · compteurs gate · métriques
  R->>R: vérification des findings prouvés (section 4)
```

## 3. Décision du gate · une requête

```mermaid
flowchart TD
  IN["requête de l'agent"] --> RELAY{"port 8081 ?"}
  RELAY -- oui --> PEER{"client = conteneur agent<br/>et chemin /v1/ ?"}
  PEER -- non --> D["403 X-BH-Gate"]
  PEER -- oui --> TOK["injecte le jeton OAuth"] --> ANT(["Anthropic"])
  RELAY -- non --> CONN["CONNECT : hôte + port jugés"]
  CONN --> SHAPE{"websocket, chemin sans /,<br/>forme absolue dans un tunnel ?"}
  SHAPE -- oui --> D
  SHAPE -- non --> NAME["destination = nom demandé<br/>IP épinglée ramenée au nom vérifié"]
  NAME --> ID{"X-BH-Identity connue ?"}
  ID -- "non : identité ignorée" --> SCOPE
  ID -- oui --> SCOPE{"scope.check<br/>+ port web + en-tête Host"}
  SCOPE -- refus --> D
  SCOPE -- passif --> PASV{"GET, chemin autorisé ?"} -- non --> D
  PASV -- oui --> UP
  SCOPE -- cible --> RULES{"méthode (override compris)<br/>écriture = identité<br/>corps ≤ 1 Mio"}
  RULES -- refus --> D
  RULES -- ok --> SCAN{"programme sans scanners :<br/>≥ 25 réponses 404 en 5 min ?"}
  SCAN -- oui --> D
  SCAN -- non --> ENUM{"plus de 4 ids distincts<br/>sur la route normalisée ?"}
  ENUM -- oui --> D
  ENUM -- non --> RATE["seau de débit · backoff 429/503/WAF"]
  RATE --> INJ["en-têtes programme · identité"] --> UP(["serveur, IP vérifiée"])
  UP --> RESP["réponse : X-BH-Gate retiré,<br/>404 comptés, flux journalisé caviardé"]
  style D fill:#fdd,stroke:#c00
  style NAME stroke-width:3px
```

## 4. Cycle de vie d'un finding

```mermaid
flowchart LR
  F["bh-note finding<br/>+ proof.json"] --> V1{"validate<br/>attaque = marqueur corps<br/>contrôle = jumeau"}
  V1 -- refus --> X["réécrire la preuve"]
  V1 -- ok --> ING["ingestion hôte<br/>preuve revalidée<br/>PoC caviardée"]
  ING --> EXC{"classe exclue<br/>par le programme ?"}
  EXC -- oui --> REJ["rejected"]
  EXC -- non --> DUP{"même classe + ressource<br/>qu'un finding actif ou rejeté ?"}
  DUP -- oui --> DUPS["duplicate"]
  DUP -- non --> RESET["process du chasseur tués<br/>HOME neuf · python -I"]
  RESET --> A["étage A · rejeu x2 via le gate<br/>contrôle qui satisfait l'attaque = réfuté"]
  A --> B["étage B · juge Opus<br/>session neuve, 8 tours"]
  B --> DEC{"A reproduit is True<br/>et B confirme ?"}
  DEC -- oui --> OK["verified<br/>PoC triager caviardée<br/>todo submit"]
  DEC -- "B rejette ou contrôle = attaque" --> REJ
  DEC -- sinon --> INC["inconclusive<br/>todo verify"]
  OK --> MIO(["Mio rejoue et soumet"])
  style OK fill:#dfd,stroke:#090
  style REJ fill:#fdd,stroke:#c00
```

## 5. Règles d'un programme · de YesWeHack au gate

```mermaid
flowchart TD
  YWH(["API publique YesWeHack"]) --> IMP["bh scope import ywh<br/>jamais d'élargissement"]
  IMP --> IGN["texte libre, plateformes partagées,<br/>assets « other », noms sans point<br/>→ listés, non appliqués"]
  IMP --> CONF["exclusions du texte qui couvrent<br/>un asset listé → conflit signalé"]
  IMP --> YAML["scopes/ywh/‹programme›.yaml"]
  YAML --> HUM{"automation_allowed<br/>scanners_allowed<br/>tranchés par Mio ?"}
  HUM -- "null" --> TODO["todo scope-question<br/>le runner refuse"]
  HUM -- oui --> ENF["application"]
  ENF --> HOOK["hooks du sandbox (aide) :<br/>table unique d'outils, verrou"]
  ENF --> GT["gate (frontière) :<br/>scope, méthodes, ports, débit,<br/>garde scanners, énumération"]
  ENF --> CLS["bh.classes : exclusions<br/>seulement si l'entrée nomme la classe"]
  style GT stroke-width:4px
```

## 6. Carte des modules · imports Python

Calculée depuis le code (`ast`, imports `bh.*`). Le code du sandbox (`bh.agent`) n'importe que la
bibliothèque standard ; le gate n'importe ni le runner ni le board.

```mermaid
flowchart LR
  subgraph SANDBOX["monté dans l'agent"]
    AGENTM["bh.agent<br/>contract · hooks · tools<br/>note · proof"]
  end
  subgraph GATEPKG["monté dans le gate"]
    GATEM["bh.gate<br/>addon · policy"]
  end
  SCOPE["bh.scope<br/>model · normalize · enforce<br/>yeswehack"]
  CLASSES["bh.classes + cards"]
  REDACT["bh.redact"]
  BOARD["bh.board"]
  ASSETS["bh.assets"]
  STACK["bh.stack"]
  RUNNER["bh.runner<br/>run · ingest · prompt · supervisor"]
  VERIFY["bh.verify"]
  UI["bh.ui"]
  CLI["bh.cli"]
  GATEM --> SCOPE
  GATEM --> AGENTM
  GATEM --> REDACT
  SCOPE --> AGENTM
  SCOPE --> CLASSES
  ASSETS --> SCOPE
  ASSETS --> BOARD
  ASSETS --> AGENTM
  STACK --> AGENTM
  RUNNER --> ASSETS
  RUNNER --> BOARD
  RUNNER --> STACK
  RUNNER --> CLASSES
  RUNNER --> REDACT
  RUNNER --> VERIFY
  VERIFY --> RUNNER
  VERIFY --> REDACT
  VERIFY --> STACK
  UI --> RUNNER
  UI --> BOARD
  CLI --> RUNNER
  CLI --> VERIFY
  CLI --> UI
  style AGENTM stroke-width:3px
  style GATEM stroke-width:3px
```

`runner ↔ verify` est le seul cycle : le vérificateur réutilise `agent_command`, `run_leg` et
`clean_sandbox` du runner, et le runner appelle `verify_pending` en fin de segment (import paresseux).

# Comparaison avec les outils étudiés

Schémas reconstruits depuis l'arborescence et le README de chaque outil (lecture GitHub du 2026-11-24).

## bull-harness

```mermaid
flowchart LR
  SUP["superviseur"] --> AG["claude -p · Kali"]
  AG --> GATE["gate · scope"]
  GATE --> T["cible"]
  AG --> REL["relais jeton"] --> LLM["Claude"]
  AG --> B[("board")]
  B --> H["Mio · todo, triage"]
  style GATE stroke-width:4px
    
```

## PentAGI

```mermaid
flowchart LR
  U["UI React"] --> API["API Go GraphQL"]
  API --> Q["file de tâches"] --> AGS["agents par rôle<br/>reflector, pentester…"]
  AGS --> SB["sandbox Docker"] --> T["cible"]
  AGS --> DB[("pgvector")]
  AGS --> KG[("Neo4j")]
  AGS --> LLM["LLM"]
    
```

## ARTEX

```mermaid
flowchart LR
  UI["Next.js"] --> SRV["serveur Go"]
  SRV --> PL["planner"] --> WK["workers ×N"]
  SRV --> MA["mainagent · humain"]
  WK --> PX["proxy MITM"] --> T["cible"]
  PL --> DB[("graphe assets<br/>+ exploration")]
  WK --> GU["guard · approbation"]
    
```

## HexStrike AI

```mermaid
flowchart LR
  LLM["Claude / GPT"] -->|MCP| M["hexstrike_mcp.py"]
  M --> S["hexstrike_server.py"]
  S --> DE["moteur de décision<br/>12 agents"]
  DE --> TL["150+ outils"] --> T["cible"]
    
```

## CyberStrikeAI

```mermaid
flowchart LR
  UI["web + chatbots"] --> H["handlers Go"]
  H --> OR["orchestration<br/>4 modes + graphes"]
  OR --> TL["recettes YAML · MCP"] --> T["cible"]
  OR --> SEC["blocage regex · RBAC"]
  H --> C2["C2 · WebShell"]
  OR --> KB[("SQLite · vecteurs")]
    
```

## Cairn

```mermaid
flowchart LR
  BB[("blackboard<br/>fact · intent · hint")]
  W1["worker CLI"] <--> BB
  W2["worker CLI"] <--> BB
  D["dispatcher"] --> W1
  D --> W2
  HU["humain · hints"] --> BB
  W1 --> T["cible"]
    
```

## sapper-v2

```mermaid
flowchart LR
  WD["watchdog · script"] --> CO["commandant<br/>lit le board"]
  CO --> GE["généraux · tmux"] --> SO["soldats · modèle léger"]
  SO --> T["cible CTF"]
  CO <--> B[("board · kb")]
    
```

## Claude-BugHunter

```mermaid
flowchart LR
  CC["session Claude Code"] --> SK["skills hunt-*<br/>à la demande"]
  CC --> CBH["cbh CLI · état"]
  CC --> PH["recon → rank → hunt"] --> G7["gate 7 questions"] --> R["rapport"]
  CC --> T["cible · depuis l'hôte"]
    
```

## bugbounty-lab101

```mermaid
flowchart LR
  SH["bugbounty-hunter.sh"] --> PR["programs/*.md"]
  SH --> SG["scope_guard.py"]
  SG --> SC["scripts · auto-scanner"] --> T["cible"]
  SC --> MV["vérif manuelle"] --> DD["duplicate_check"]
    
```
