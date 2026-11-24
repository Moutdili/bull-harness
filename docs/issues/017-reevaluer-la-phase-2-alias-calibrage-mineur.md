---
id: 17
title: "Réévaluer la phase 2 (alias, calibrage, mineur)"
labels: [P1, area:tokens, owner:claude, research-check]
status: closed
---

# Réévaluer la phase 2 (alias, calibrage, mineur)

Les commandes pèsent peu face aux observations.

**Acceptation :** décision écrite, chiffres de la mesure P0 à l'appui

Plan : [docs/plan-v3.md](../plan-v3.md)

## Mesure du 2026-11-24

- Calibrage (`bh tokens calibrate`, Sonnet 5.5, contexte `cd /tmp; {}/rest/x`) : 4 231 candidats mesurés,
  124 symboles à 1 token (49 ASCII, 28 hiragana, 19 cyrillique…). Table : `src/bh/tokens/symbols.json`.
- Mineur corrigé : heredocs, séparateurs entre guillemets et fonctions shell ne créent plus de faux préfixes
  (`E`, `no`, `b`, `F1-F5,F11` disparus).
- Corpus : 20 runs lab, 135 commandes Bash, médiane 6,5 tours par run.
- `bh tokens mine --turns 7` : 4 alias rentables (`curl -s` 59, `bh-note` 51, `head -c` 14, `echo` 8), soit
  ~132 éq. tokens d'entrée par run.
- Coût réel d'un run (usage des logs, entrée + 5×sortie + 0,1×lecture cache + 2×écriture cache) :
  médiane 24 923 éq., moyenne 32 696. La sortie pèse ~10 % ; l'écriture et la lecture de cache dominent.
- Gain des alias : ~0,5 % d'un run. Sans `curl -s` (déjà remplacé par `q`) : ~0,3 %.

## Décision (validée par Mio le 2026-11-25)

Ne pas compiler d'alias. Le gain est sous le bruit et le coût est réel : une couche d'expansion dans les hooks,
une légende qui change le prompt système, des symboles que le modèle peut confondre.
Le calibrage et le mineur restent comme veille : on relance `bh tokens mine` quand les runs dépassent 30 tours
ou quand `q`/`qq` ont remplacé `curl` dans les logs.
Le vrai levier est côté observations (issue 010) et sorties tronquées (`q`, 2.2).
