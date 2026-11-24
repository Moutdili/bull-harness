# Diagrammes d'architecture

Sources mermaid de la revue du 2026-11-24 (skill `improve-codebase-architecture`).
Page rendue : artifact « bull-harness architecture ». Les schémas des outils tiers sont reconstruits
depuis leur arborescence et leur README (lecture GitHub du 2026-11-24).

## Runtime · qui parle à qui

```mermaid
flowchart LR
  MIO["Mio"] --> UI
  subgraph HOST["Hôte Fedora · podman rootless"]
    CLI["bh CLI"] --> RUN["runner.run · segment"]
    SUP["runner.supervisor · hunt"] --> RUN
    UI["ui.server · Tailscale + session HMAC"]
    ING["runner.ingest"]
    BOARD[("board.sqlite<br/>facts · intents · findings<br/>todos · runs")]
    STATE[("var/state<br/>active-scope · active-run<br/>flows · events · identities")]
    RUN --> BOARD
    ING --> BOARD
    UI --> BOARD
    RUN -->|"active-scope, active-run"| STATE
  end
  subgraph AGENT["Conteneur agent · Kali · réseau sandbox interne"]
    CL["claude -p · jeton factice"]
    HK["hooks · verrou d'outils, troncature"]
    BI["builtins bh-recon crawl content<br/>scan params sqli xss"]
    NOTE["bh-note"]
    WD[("/work/prog/.bh<br/>coverage · endpoints · touched · notes")]
    CL --> HK
    CL --> BI
    CL --> NOTE
    BI --> WD
    NOTE --> WD
    HK --> WD
  end
  subgraph GATE["Conteneur gate · mitmproxy · seul sur egress"]
    PX[":8080 proxy<br/>scope · méthodes · énumération<br/>débit · identités · journal"]
    RL[":8081 relais Claude<br/>injecte le vrai jeton OAuth"]
  end
  RUN -->|"podman exec claude -p"| CL
  WD -->|"notes pivotées"| ING
  CL -->|"ANTHROPIC_BASE_URL"| RL --> ANTH["api.anthropic.com"]
  BI -->|"HTTP(S)_PROXY"| PX
  PX -->|"dans le scope"| TGT["Cible du programme"]
  PX -->|"GET passif"| PAS["crt.sh · archive · OTX"]
  PX --> STATE
  STATE -->|"events"| ING
    
```

## Un segment · séquence

```mermaid
sequenceDiagram
  participant R as runner.run
  participant B as board
  participant S as stack (podman)
  participant A as claude (agent)
  participant G as gate
  R->>R: run.lock, scope actif
  R->>B: run_start (ferme un orphelin)
  R->>S: clean_sandbox, push frontier · doctrine
  R->>G: active-run.json
  loop jusqu'à 3 legs
    R->>S: podman exec claude -p
    A->>G: requêtes outils (8080) · LLM (8081)
    G-->>R: stream-json via stdout
  end
  R->>S: rotate notes
  R->>B: ingest notes + events, run_end
      
```

## Décision du gate · une requête

```mermaid
flowchart TD
  Q["Requête de l'agent"] --> T{"TCP brut ?"}
  T -->|oui| K["coupé"]
  T -->|non| D{"Destination réelle<br/>dans le scope ?"}
  D -->|"hors scope explicite"| X["403"]
  D -->|"non listée"| P{"Source passive<br/>GET sans corps ?"}
  P -->|non| X
  P -->|oui| OKP["passif · sans en-têtes"]
  D -->|oui| H{"Host ≠ destination<br/>hors scope ?"}
  H -->|oui| X
  H -->|non| M{"Méthode, identité,<br/>taille, énumération"}
  M -->|refus| X
  M -->|ok| OKT["cible · débit, en-têtes<br/>programme, identité"]
      
```

## Carte des modules · imports Python

```mermaid
flowchart LR
  subgraph scope["bh.scope"]
    NORM["normalize"] --> MODEL["model"]
    NORM --> ENF["enforce"]
    MODEL --> ENF
  end
  subgraph agent["bh.agent · sandbox"]
    CON["contract"]
    HOOKS["hooks"] --> CON
    NOTEM["note"] --> CON
    TOOLS["tools"] --> CON
    MAIN["main"] --> HOOKS
    MAIN --> NOTEM
    MAIN --> TOOLS
  end
  subgraph gate["bh.gate"]
    POL["policy"] --> CON
    POL --> ENF
    ADD["addon"] --> POL
    ADD --> CON
  end
  PATHS["paths"]
  STACK["stack"] --> PATHS
  STACK --> CON
  BOARDM["board"] --> PATHS
  subgraph runner["bh.runner"]
    PROMPT["prompt"]
    INGEST["ingest"]
    RUNM["run"] --> INGEST
    RUNM --> PROMPT
    SUPM["supervisor"] --> RUNM
  end
  ADD --> PATHS
  PROMPT --> MODEL
  INGEST --> BOARDM
  INGEST --> CON
  RUNM --> STACK
  RUNM --> BOARDM
  RUNM --> CON
  UIM["ui.server"] --> BOARDM
  UIM --> STACK
  CLIM["cli"] --> RUNM
  CLIM --> SUPM
  CLIM --> UIM
    
```

## Avant

```mermaid
flowchart TD
  MP["mitmproxy hooks"] --> ADD["addon.py · non testé<br/>identité, en-têtes, WAF,<br/>relais, caviardage, fail_closed"]
  ADD --> POL["policy.py · 13 tests"]
  POL -.->|"parseurs URL laxistes"| CON["contract.origin/path_key"]
  linkStyle 2 stroke:#b42318
      
```

## Après

```mermaid
flowchart TD
  MP["mitmproxy · adapter mince"] -.-> CORE["Décision de requête<br/>données → verdict + réécritures<br/>+ lignes de journal"]
  T["pytest · escape suite"] -.-> CORE
  CORE --> NORM["scope.normalize · seul parseur"]
  style CORE stroke-width:4px
      
```

## Avant

```mermaid
flowchart TD
  RL["_run_locked · 12 étapes ordonnées"] --> SH1["clean_sandbox · rm -rf en shell"]
  RL --> SH2["rotate_notes · mv en shell"]
  RL --> SH3["agent_command · wrapper sh"]
  RL --> ST["stack.push_file / kill_agent"]
  RL -.->|"statut décidé à 4 endroits"| SUP["supervisor, cli"]
  linkStyle 4 stroke:#b42318
      
```

## Après

```mermaid
flowchart TD
  RUN["run.py · politique<br/>legs, relances, budget"] --> SB["Sandbox<br/>wipe · push · launch leg<br/>stop · collect inbox"]
  SB -.-> PODMAN["adapter podman"]
  SB -.-> LOCAL["adapter dossier local<br/>+ stream rejoué"]
  RUN --> OUT["Issue du segment · une décision"]
  style SB stroke-width:4px
      
```

## Avant · « testé » vient de 7 endroits

```mermaid
flowchart LR
  H["hooks · URL littérales"] --> S["surface()"]
  TL["tools · record_touched"] --> S
  F["flows.jsonl · relu 4× par segment"] --> MT["run.manually_tested"] --> S
  MT -.->|"instantané figé"| N["bh-note frontier"]
  linkStyle 3 stroke:#b42318
      
```

## Après

```mermaid
flowchart LR
  EV1["preuve sandbox · falsifiable"] --> SURF["Surface<br/>endpoints · couverture · testé<br/>rendu du frontier"]
  EV2["preuve gate · fait foi"] --> SURF
  SURF --> HOST["runner + supervisor"]
  SURF --> AG["bh-note"]
  style SURF stroke-width:4px
      
```

## Avant

```mermaid
flowchart LR
  W["Gate._log / _record<br/>seuls à définir le format"] --> E[("events · flows")]
  E --> R1["ingest"]
  E --> R2["run"]
  E --> R3["cli"]
  E --> R4["ui + app.js"]
  ID["ui._save_identity<br/>+ script lab"] --> I[("identities")] --> A["addon"]
      
```

## Après

```mermaid
flowchart LR
  J["Journal du gate<br/>format · curseur par programme<br/>sens de manuel"] --> C["ingest · run · cli · ui"]
  IS["Identity store<br/>format · nom · liste"] --> C2["ui · addon · lab"]
  style J stroke-width:4px
  style IS stroke-width:4px
      
```

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
