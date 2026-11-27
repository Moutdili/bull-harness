# Schémas d'architecture

Redessinés en W4 (lot G) depuis le code à `b160269` (W1 à W3 fusionnées). Cinq schémas, rien d'autre : chaque boîte et
chaque flèche renvoie à un `fichier:ligne` cité sous le schéma. Ce qui n'existe pas encore dans le dépôt porte la
mention « W4 » et un trait pointillé. `tests/test_w4_docs.py` vérifie que les chemins, les services et les statuts cités
existent.

## 1. Runtime : qui parle à qui

L'agent n'a qu'une sortie : le gate, seul conteneur sur `egress`. Il voit son `/work`, le code de la sandbox, les skills
et les hooks, en lecture seule sauf `/work` ; jamais `secrets/`, `var/state`, `var/lineage`, `var/rules`,
`.claude/skills` ni le board. L'écouteur hors bande (W4) reçoit les rappels d'un serveur cible, jamais l'agent.

```mermaid
flowchart LR
  MIO(["Mio"]) -->|"bh CLI"| HRUN
  MIO -->|"navigateur, IP Tailscale ou 127.0.0.1"| UI
  subgraph HOST["hôte · podman rootless · rien de ceci n'est monté dans agent ni judge"]
    HRUN["runner · supervisor · verify<br/>thread serveur de bh-recall"]
    UI["ui :7340 · jeton puis cookie HMAC"]
    BOARD[("var/board.sqlite<br/>board et mémoire de la lignée")]
    PRIV[("secrets/ · var/lineage · var/rules<br/>.claude/skills")]
    STATE[("var/state<br/>scope actif · run actif · flows · events")]
    HRUN --> BOARD
    UI --> BOARD
    HRUN --> STATE
  end
  subgraph SANDBOX["réseau sandbox · internal : aucune route"]
    AGENT["agent<br/>claude -p · hooks Bash et mcp__.*<br/>MCP stdio bh, hexstrike<br/>/work = var/work · src/bh/agent ro<br/>src/bh/skills ro · container/agent/hooks ro"]:::ctr
    JUDGE["judge<br/>/work = var/judge · aucun skill"]:::ctr
    LOGIN["login<br/>Chromium de connexion, sans /work"]:::ctr
    BROWSER["browser · profil<br/>navigateur persistant, API :8790"]:::ctr
    AUDIT["audit · profil<br/>copie du code sous /work"]:::ctr
  end
  GATE["gate · mitmproxy<br/>:8080 politique · :8081 relais<br/>réseaux sandbox, egress, lab"]:::ctr
  subgraph LABNET["réseau lab · internal"]
    JUICE["juiceshop · profil lab"]:::ctr
  end
  HRUN -->|"podman exec"| AGENT
  HRUN -->|"podman exec, preuve poussée"| JUDGE
  HRUN -->|"podman exec, recette de login"| LOGIN
  UI -->|"podman exec, écran relayé"| BROWSER
  AGENT -->|"BH_BROWSER_TOKEN"| BROWSER
  AGENT -->|":8080 proxy"| GATE
  AGENT -->|":8081 API Claude"| GATE
  JUDGE -->|":8080 et :8081"| GATE
  AUDIT -->|":8081 API Claude"| GATE
  LOGIN -->|":8080 proxy"| GATE
  BROWSER -->|":8080 proxy"| GATE
  STATE -. "monté dans le gate" .- GATE
  PRIV -. "secrets/agent.env : jeton OAuth, gate seul" .- GATE
  GATE -->|"egress"| TGT(["cibles du scope"])
  GATE -->|"egress"| OTH(["support, passifs, docs,<br/>hôtes de charge"])
  GATE -->|"egress, jeton posé"| ANT(["api.anthropic.com"])
  GATE -->|"lab"| JUICE
  TGT -. "rappel du serveur cible, W4" .-> FUN(["Tailscale Funnel, W4"])
  FUN -.-> OOB["oob · écouteur hors bande, W4<br/>réseau oob, seul ; port lié à la boucle locale de l'hôte"]:::ctr
  OOB -. "journal lu par l'hôte, W4" .-> HRUN
  class OOB,FUN w4
  classDef ctr stroke-width:2px
  classDef w4 stroke-dasharray:5 5
  style GATE stroke-width:4px
```

Sources :
- réseaux et services : `container/compose.yaml:29-36` (`sandbox` et `lab` internes), `:43-76` (gate, ses montages
  `:64-68`, `secrets/agent.env` `:59-60`, réseaux `:69`), `:78-114` (agent : `/work` `:100`, `src/bh/agent` `:105`,
  skills `:110`, hooks `:102`, réseau `:113`, `BH_BROWSER_URL` `:97`), `:120-139` (judge, `var/judge` `:133`),
  `:144-165` (audit), `:173-194` (login), `:204-236` (browser), `:239-246` (juiceshop) ;
- proxy et relais : `container/compose.yaml:11-27` (`HTTP_PROXY`, `ANTHROPIC_BASE_URL`), `:51-54` ;
  `src/bh/gate/addon.py:838-883` (relais, rôles agent, judge, audit) ;
- seule variable venue de `secrets/` dans agent et browser : `BH_BROWSER_TOKEN`, clé de l'API étroite de bh-browser
  (`container/compose.yaml:90-92`, `:215-217`) ; `.claude` n'est monté nulle part (`tests/test_w1_docs.py`) ;
- `var/lineage` et `lab/` jamais montés : `container/compose.yaml:6-7` ; `var/rules` : `src/bh/rules.py:1-6` ;
- hôte : `src/bh/paths.py:66-67` (board), `src/bh/ui/server.py:1-5` et `:795` (UI), `src/bh/lineage/serve.py:1-11`
  (bh-recall par fichiers), `src/bh/runner/run.py:2655-2668` (`podman exec` du chasseur) ;
- W4, lot A : service `oob`, écouteur lié à la boucle locale, publié par Tailscale Funnel (brief W4-G, item 1).

## 2. Un segment, en séquence

Du `bh hunt --phase` à la clôture. Les plafonds et les règles refusent avant tout : rien n'attend un humain. Le
`bh-recall` de l'agent est servi par un thread du runner, par fichiers, pendant toute la durée du segment.

```mermaid
sequenceDiagram
  autonumber
  participant M as Mio (bh hunt)
  participant S as supervisor
  participant R as runner
  participant G as gate
  participant A as agent (claude -p)
  participant H as hooks
  participant L as lignée et board
  participant J as judge
  M->>S: bh hunt --phase P
  S->>S: préflight : programme prêt, règles fraîches (bh rules), moins de 3 refus en 7 jours
  S->>S: session ouverte (11 runs, 3 sessions et 33 runs par jour)
  S->>R: run_segment
  R->>R: programme parqué ou non prêt : refus · verrou var/run.lock
  R->>R: admit : plafonds de phase, de jour et de session, refus sans attente
  R->>G: auto-test du gate (suite d'évasion, profil lab, puis profil msrc si passthrough)
  R->>G: scope actif écrit
  R->>R: sandbox nettoyée, sessions des identités rafraîchies, arsenal vérifié
  R->>L: fiche du setup hachée (record_setup)
  R->>L: naissance de l'agent, trace ouverte, serveur bh-recall démarré
  R->>L: bloc Lineage de la tâche (60 lignes au plus)
  R->>G: liste des destinataires (empreintes), run actif et budget du relais
  loop jambes, tant que tours, temps et contexte le permettent
    R->>A: podman exec claude -p (tâche ou relance)
    A->>H: Bash ou mcp__* : PreToolUse
    H-->>A: refus (verrou d'outils, règles du programme) ou passage
    A->>G: HTTP par :8080, API Claude par :8081
    G-->>A: réponse ou 403 X-BH-Gate
    A->>R: bh-recall : fichier de requête
    R-->>A: réponse bornée et reçu R-id
    A->>H: PostToolUse : sortie tronquée, brut sous raw/
    alt contexte au-delà du seuil
      R->>L: rotation : agent clos, un autre naît, parent l'ancien
    else la jambe s'arrête tôt
      R->>A: même session relancée
    end
  end
  R->>G: run actif retiré
  R->>L: ingestion des notes et des événements du gate (finish)
  R->>J: vérification des findings en attente (verify_pending)
  R->>L: clôture : mémoire, reçus, registre de crédit, archive, bloc de chaîne
```

Sources :
- `bh hunt` : `src/bh/cli.py:1204` (`--phase`), `src/bh/runner/supervisor.py:241-262` (préflight : `check_automation`,
  `rules_fresh` `:224-238`, refus en 7 jours), `:275-303` (session), `:46-49` (plafonds), `:128-150` (`admit`) ;
- segment : `src/bh/runner/run.py:2431-2494` (`run_segment` : `check_automation` `:2459`, `run_lock` `:2468`,
  `admit` `:2469`, auto-test `:2470-2476`), `src/bh/runner/preflight.py:1-16` (suite d'évasion, profils) ;
- `_run_locked` : `src/bh/runner/run.py:2523` (scope actif), `:2540-2550` (sandbox, identités, arsenal),
  `:2584-2597` (setup haché), `:2599` (naissance), `:2602` (bloc), `:2619` (destinataires), `:2637` (run actif et
  budget), `:2645-2793` (jambes, rotation `:2742-2779`, relance `:2780-2785`), `:2816` (run actif retiré), `:2835`
  (`finish`), `:2840-2856` (vérification), `:2861` (clôture) ;
- hooks : `container/agent/hooks/settings.json` (PreToolUse et PostToolUse sur `Bash` et `mcp__.*`) ;
- lignée : `src/bh/runner/lineage_hooks.py:97-139` (naissance, trace, serveur), `:173-180` (rotation), `:194-237`
  (clôture) ; `src/bh/lineage/serve.py:82-116` ; `src/bh/agent/recall.py:1-13` ;
- ingestion : `src/bh/runner/run.py:1505-1517`, `src/bh/runner/ingest.py:131`, `:601`.

## 3. Décision du gate pour une requête

L'ordre est celui du code : `addon.request` puis `Policy.classify_request` puis `Policy._classify`, enfin le seau de
débit et l'injection. Le premier refus répond `403` avec `X-BH-Gate` et une raison ; rien d'autre ne part.

```mermaid
flowchart TD
  IN(["requête d'un client du réseau sandbox"]) --> PORT{"écouteur :8081 ?"}
  PORT -- oui --> REL{"client agent, judge ou audit,<br/>appel que fait Claude Code, run actif,<br/>corps accepté, budget restant ?"}
  REL -- non --> D["403 X-BH-Gate"]
  REL -- oui --> TOK["jeton OAuth du gate posé"] --> ANT(["api.anthropic.com"])
  PORT -- "non, :8080" --> CONN{"CONNECT : classe de destination<br/>API Claude, le gate, port, passthrough<br/>réservé à bh-browser, pause WAF"}
  CONN -- refus --> D
  CONN -- ok --> REQ["requête déchiffrée : X-BH-Identity retiré,<br/>nom inconnu ignoré, bh-browser : identité de l'hôte<br/>canaris cherchés dans l'URL et le corps"]
  REQ --> SHAPE{"cible sans / initial ou<br/>forme absolue dans un tunnel ?"}
  SHAPE -- oui --> D
  SHAPE -- non --> SYS{"API Claude ou adresse du gate ?"}
  SYS -- oui --> D
  SYS -- non --> SC["scope.check : cible, support,<br/>règle d'exclusion ou rien"]
  SC --> PROT{"URL protégée ?<br/>déconnexion, mot de passe, compte,<br/>paiement, protected_urls"}
  PROT -- oui --> D
  PROT -- non --> RCP{"route de recipient_guard sans adresse<br/>ou avec une adresse qui n'est pas à nous ?"}
  RCP -- oui --> D
  RCP -- non --> WS{"handshake websocket ?"}
  WS -- oui --> WSOK{"websockets: true, cible, GET,<br/>bh-browser si passthrough, moins de 2 ouverts ?"}
  WSOK -- non --> D
  WSOK -- oui --> KIND
  WS -- non --> KIND{"classe"}
  KIND -- support --> SUP{"assets, auth, sso : client, port,<br/>méthode, get_paths, token_paths ?<br/>passthrough déchiffré : refus"}
  SUP -- non --> D
  KIND -- cible --> BO{"préfixe browser_only et client<br/>autre que bh-browser ?"}
  BO -- oui --> D
  BO -- non --> WAF{"hôte en pause WAF ?<br/>bh-browser exempté"}
  WAF -- oui --> D
  WAF -- non --> HOSTH{"port web, en-tête Host dans le scope ?"}
  HOSTH -- non --> D
  HOSTH -- oui --> METH{"méthode permise, PUT PATCH DELETE<br/>sous une identité, corps 1 Mio au plus ?"}
  METH -- non --> D
  METH -- oui --> SCAN{"programme sans scanners : 25 réponses 404<br/>en 5 min sur l'origine ? bh-browser exempté"}
  SCAN -- oui --> D
  SCAN -- non --> ENUM{"plus de policy.ID_LIMIT ids distincts dans le<br/>chemin de la route, en 10 min ?"}
  ENUM -- oui --> D
  KIND -- "règle d'exclusion" --> D
  KIND -- "hors scope" --> OTH{"source passive, docs<br/>ou hôte de charge ?"}
  OTH -- non --> D
  OTH -- passif --> PAS{"GET ou HEAD sans corps,<br/>même Host, chemin permis ?"}
  OTH -- docs --> DOC{"GET ou HEAD, ni identité ni cookie,<br/>requête sans nom du scope, 10 par minute ?"}
  OTH -- charge --> PAY{"GET, HEAD ou OPTIONS sans corps ?"}
  PAS -- non --> D
  DOC -- non --> D
  PAY -- non --> D
  SUP -- oui --> RATE
  ENUM -- non --> RATE
  PAS -- oui --> RATE
  DOC -- oui --> RATE
  PAY -- oui --> RATE["seau de débit de la classe<br/>cible : débit du programme, réduit après 429, 503 ou WAF"]
  RATE --> INJ{"cible : en-têtes du programme, identité injectée<br/>sso : cookies de la jarre · docs : en-têtes réduits<br/>passif, charge, assets : ni Cookie ni Authorization"}
  INJ -- "jeton de l'identité expiré" --> D
  INJ -- ok --> IP{"connexion amont : chaque IP résolue<br/>vérifiée par check_ip, puis épinglée"}
  IP -- refus --> D
  IP -- ok --> UP(["serveur"])
  UP --> RESP["réponse : X-BH-Gate retiré, canaris cherchés,<br/>redirection vers passthrough sous identité refusée,<br/>404 et WAF comptés, flux journalisé caviardé"]
  style D fill:#fdd,stroke:#c00
```

Sources :
- relais : `src/bh/gate/addon.py:896-902`, `:838-883` ; `src/bh/gate/policy.py:1215` (`check_relay`) ;
- CONNECT : `src/bh/gate/addon.py:657-676`, `src/bh/gate/policy.py:343-370` (`classify_connect`) ;
- requête : `src/bh/gate/addon.py:903-950` (identité `:904-920`, canaris `:921-922`, `/` initial `:923-925`, forme
  absolue `:930-932`, appel `:936`) ;
- `classify_request` : `src/bh/gate/policy.py:399-448` (API Claude et gate `:421-424`, scope `:425` et `:315-327`,
  URL protégées `:426-427` et `:116-121`, destinataires `:428-432` et `:372-397`) ;
- `_classify` : `src/bh/gate/policy.py:450-516` (websocket `:465-475`, support `:476-479` et `:539-583`, cible
  `:480-498` : `browser_only` `:481-482`, pause WAF `:483-484` et `:701-715`, port `:485-486`, Host `:487-490`, méthode
  et identité `:491-494`, corps `:495-496`, garde 404 `:497` et `:603-616`, énumération `:498` et `:618-649`,
  `ID_LIMIT` `:112`), exclusion `:499-500`, passif `:501-509`, docs `:510-513` et `:518-537`, charge `:514-515` et
  `:883`, refus final `:516` ;
- débit et injection : `src/bh/gate/addon.py:957-992`, `src/bh/gate/policy.py:675-728`, refus du jeton
  `src/bh/gate/addon.py:1039-1064` ;
- IP : `src/bh/gate/addon.py:797-831`, `src/bh/gate/policy.py:651-672` ;
- réponse : `src/bh/gate/addon.py:1146-1207`.

## 4. Cycle de vie d'un finding

Les neuf boîtes rouges, vertes et grises sont les statuts de `FINDING_STATUS`, et rien d'autre. Seuls `verified` et
`verified-evidence` ouvrent la todo `submit` ; Mio soumet. Le double cadrage et l'issue plateforme sont de W4.

```mermaid
flowchart LR
  NOTE["bh-note finding<br/>--proof proof.json ou --observation canari"] --> VAL{"preuve valide à l'écriture ?<br/>contrôle jumeau"}
  VAL -- non --> REW["refusée : à réécrire"]
  VAL -- oui --> ING["ingestion hôte<br/>preuve revalidée, caviardée"]
  ING --> EXC{"classe exclue<br/>par le programme ?"}
  EXC -- oui --> REJ["rejected"]:::status
  EXC -- non --> NEW["new"]:::status
  NEW --> VP["verify_pending, fin de segment"]
  VP --> OBS{"preuve par observation ?"}
  OBS -- oui --> HOBS{"l'hôte relit les événements canary :<br/>vu côté attaquant, contrôle 0 sur N ?"}
  HOBS -- "non vu, ou contrôle franchi" --> INC["inconclusive"]:::status
  HOBS -- "envoyé par l'attaquant" --> REJ
  HOBS -- vu --> JOB["juge, une session<br/>peut baisser, jamais monter"]
  JOB -- confirme --> VE["verified-evidence"]:::status
  JOB -- rejette --> REJ
  JOB -- sinon --> INC
  OBS -- non --> DUP{"même classe et ressource<br/>qu'un finding actif ?"}
  DUP -- oui --> DUPS["duplicate"]:::status
  DUP -- non --> WAIT{"hôte en pause WAF ?"}
  WAIT -- oui --> NEW
  WAIT -- non --> VING["verifying"]:::status
  VING --> A["étage A : rejeu x2 via le gate<br/>conteneur judge, utilisateur judge"]
  A -- "pas refusé par le gate" --> CTRL{"contrôle jumeau<br/>répond comme l'attaque ?"}
  A -- "refusé par le gate" --> NEW
  CTRL -- "1re fois" --> NP["needs-proof"]:::status
  NP -- "nouvelle preuve, même titre" --> NEW
  CTRL -- "2e fois" --> REJ
  CTRL -- non --> B["étage B : juge neuf, nonce<br/>inconclusive : second juge, une fois"]
  B --> DEC{"A reproduit<br/>et B confirme ?"}
  DEC -- oui --> OK["verified"]:::status
  DEC -- "B rejette" --> REJ
  DEC -- sinon --> INC
  INC -. "W4, lot C : double cadrage,<br/>éteint par défaut" .-> DC["deux passes à cadrage opposé"]
  OK --> TODO["todo submit<br/>PoC du trieur caviardée"]
  VE --> TODO
  TODO --> MIO(["Mio rejoue et soumet"])
  MIO --> SUB["submitted"]:::status
  SUB -. "W4, lot E : bh outcome ou bouton de l'UI" .-> ISS["issue plateforme"]
  class DC,ISS w4
  classDef status stroke-width:3px
  classDef w4 stroke-dasharray:5 5
  style OK fill:#dfd,stroke:#090
  style VE fill:#dfd,stroke:#090
  style REJ fill:#fdd,stroke:#c00
```

Sources :
- statuts : `src/bh/board/db.py:135-146` (`FINDING_STATUS`) ;
- écriture et ingestion : `src/bh/agent/note.py` (`bh-note finding`), `src/bh/runner/ingest.py:240-253` (finding
  `new`, classe exclue `rejected`), `:195` (nouvelle preuve après `needs-proof`) ;
- vérification : `src/bh/verify.py:1-25` (table de décision), `:455-495` (`verify_finding` : observation `:464-465`,
  doublon `:472-475`, pause WAF `:479-482`, `verifying` `:483`), `:498-546` (`_verify` : étage A `:507`, refus du gate
  `:512-513`, `needs-proof` `:514-515` et `:279-298`, étage B `:517`, second juge `:519-533`, todo `submit` `:538-545`),
  `:227-237` (`decide`), `:263-276` (`_defer` : retour à `new`) ;
- observation : `src/bh/verify.py:579-588` (`decide_observation`), `:603-647`, `src/bh/runner/observation.py:75-135`
  (envoyé par l'attaquant : `rejected` ; contrôle franchi : `inconclusive`), `:166` ;
- soumission : `src/bh/cli.py:388` (`bh finding --set submitted`), `src/bh/ui/server.py:702` ;
- W4, lot C : double cadrage (`BH_DOUBLE_FRAMING=1`, défaut 0) ; W4, lot E : `bh outcome`.

## 5. Lignée et mémoire

Chaque session `claude -p` est un agent numéroté qui laisse des items typés à ses successeurs. L'étiquette vient de
l'hôte, jamais du texte de l'agent ; toute requête filtre par programme : rien ne traverse les programmes, sauf les
fiches de technique (W4).

```mermaid
flowchart LR
  subgraph SBX["sandbox · agent"]
    BN["bh-note : fact, recon, handoff, dead-end,<br/>think, threat-model, intent, cover, finding"]
    BR["bh-recall ‹idée›<br/>requête en fichier sous /work"]
  end
  subgraph HST["hôte · board.sqlite et var/lineage, par programme"]
    ING["ingestion : types vérifiés,<br/>citations relues, caviardage"]
    BRD[("facts · intents · findings · runs")]
    MEM["mem_items · étiquette de l'hôte<br/>OBSERVED · JUDGED · ANCHORED · NOTE"]
    KEY["clé canonique<br/>hôte, route, classe, technique, ids"]
    FTS["mem_fts · FTS5"]
    SRV["serveur bh-recall<br/>thread du runner"]
    RCPT["mem_receipts · reçu R-id"]
    BLK["bloc Lineage de la tâche<br/>60 lignes au plus"]
    AGT["agents · numéro, pseudo, parent"]
    TRC["trace de l'agent · chaîne de hash"]
    CHN["blocks · un bloc par agent clos,<br/>chaîné au précédent du programme"]
    LED["ledger · registre de crédit"]
    ARC[("archive caviardée de l'agent")]
  end
  BN --> ING --> BRD
  BRD -- "clôture de l'agent" --> MEM
  MEM --> KEY
  MEM --> FTS
  BR -. "req et res en fichiers" .-> SRV
  SRV --> FTS
  SRV --> RCPT
  SRV -. "réponse bornée, données balisées" .-> BR
  RCPT -- "intent cite --recall R-id" --> BRD
  MEM --> BLK
  BRD --> BLK
  BLK -- "tâche du segment" --> SBX
  AGT --> TRC --> CHN
  BRD --> LED
  MEM --> LED
  AGT --> ARC
  NEVER["jamais d'un programme à l'autre :<br/>items, reçus, blocs, archives"]
  TECH["fiches de technique, W4 lot F :<br/>seule exception entre programmes"]
  MEM --- NEVER
  TECH -.- NEVER
  class TECH w4
  classDef w4 stroke-dasharray:5 5
```

Sources :
- notes typées : `src/bh/agent/contract.py:171-182` (`FACT_KINDS`, `INTENT_KINDS`), `src/bh/agent/note.py` ;
- ingestion : `src/bh/runner/ingest.py:131` (`notes`), `src/bh/runner/lineage_hooks.py:194-237` (clôture : mémoire
  `:208`, reçus `:209`, score `:210`, archive `:211-222`, bloc `:231`, identité `:232`) ;
- mémoire : `src/bh/lineage/store.py:1-20` (tables, règles, « every query filters by program »), `:71` (FTS5), `:77`
  (`LABELS`), `:678` (`ingest_run`) ; clé : `src/bh/lineage/key.py:1-7`, `:76` (`canonical`) ;
- rappel : `src/bh/agent/recall.py:1-13`, `src/bh/lineage/serve.py:1-11`, `src/bh/lineage/recall.py:1-20`, `:277`
  (filtre `m.program=?`), `:372` (`search`), `:680` (`mark_intents`) ;
- bloc : `src/bh/lineage/block.py:1-14`, `:333` (`build`) ; agents : `src/bh/lineage/identity.py:83` (`birth`), `:122`
  (`close`) ; chaîne : `src/bh/lineage/chain.py:1-12`, `:73`, `:147` ; registre : `src/bh/lineage/score.py:1-12`,
  `:79`, `:436` ; archive : `src/bh/lineage/archive.py:1-9` ;
- W4, lot F : fiches de technique, seules partagées entre programmes (brief W4-G, item 5).
