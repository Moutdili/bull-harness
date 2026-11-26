---
name: token-cost-of-commands
description: Use when designing or renaming a command, a builtin or a tool the agent will type often, or when measuring what a short form really saves. Cost model, naming rules, and how to measure on Claude.
---
Source: hermes/token-efficient-agent-commands/SKILL.md (author: Hermes Agent, licence: MIT).
Modified: translated; token counts measured on other models' tokenizers removed (they do not transfer); the non-ASCII one-character names and the Hermes plugin steps removed; the audit argument and the "In this repository" section are ours. Its probe script and reference were not repatriated.
Role: harness developer. This is the knowledge behind `q`, `qq` and the `tokens/` part of the architecture.

# Token cost of the commands an agent types

## When
- A command line the agent repeats is long (a proxy flag, an identity header, a pipeline).
- Before adding an alias, a wrapper or a new tool name.

## Cost model
A command is paid twice:
1. as output, when the model writes it (full price);
2. as input, on every later turn while it stays in the history (cached, about a tenth of the price).
Saving is about `(tokens of the command - tokens of the short form) x (1 + remaining turns)`, minus the cost
of the table that teaches the short form, which is also resent every turn.

## Do
1. Measure on the model that will type it. A token is not a character, and tokenizers differ: never assume.
   Here: a differential run with `claude -p --output-format json`, reading `usage` with and without the
   short form, several times (the cache adds noise).
2. Name it readable: verb plus object, common English words. A word a human cannot read in a log is not a
   saving in a security harness: every command is audited and classified by name.
3. Compile to wrappers, not shell aliases: a small script on the PATH that passes `"$@"` and logs. Shell
   aliases do not expand in non-interactive shells or sub-agents.
4. Index, not expansion: what the agent always sees is `name -> short intent`; the expansion lives in the
   wrapper and in a `help` output.
5. Mine before inventing: read the commands agents really typed (the hooks' log), extract prefix plus
   argument slots, rank by saving times frequency. Count only exact literals and literal prefixes; count
   each command once, against its longest match.
6. Teach once: one notice per short form and per session, appended to a tool output ("this line cost about
   N tokens; `<name>` does the same"). Inject the index after the system prompt so the cached prefix stays
   stable; never re-inject it.
7. Measure adoption, not potential: does the agent use the short form, and how often does it fail?

## Never
- Rewrite the agent's command silently to "save tokens": they were spent when it was generated, and a
  transcript that differs from what ran is a lie. (Routing a command through an output filter is another
  matter: that saves the output, and must show in the log.)
- A name that already resolves (a binary on the PATH, a shell builtin, a reserved word): the wrapper would
  mask the real one.
- A short form for a destructive command: it hides the intent in the logs.
- A fixed alias where an argument varies: generate wrappers that take arguments.
- A long table: keep the top entries by measured saving and retire the cold ones.

## Checks
- The short form and the long form produce the same output, side by side.
- `bash -c '<name> arg'` and `sh -c '<name> arg'` both work and pass the argument.
- The register shows net savings: gains minus the cost of the table.

## In this repository
- `q` and `qq` are this idea applied: one request per line, short summary, body saved to a file.
- Long outputs are cut by a hook and saved; the path is shown. The same accounting applies to outputs.
- The token calibration and mining commands of the CLI are on hold; this skill is the method to restart
  them from, not a claim that aliases pay.
