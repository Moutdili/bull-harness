---
name: claude-p-headless
description: Use when writing or debugging code that launches `claude -p` (the runner, the judge, a sub-agent lot): output formats, result fields, session resume, where transcripts live and what to read in them.
---
Source: hermes/.archive/claude-code/SKILL.md (author: Hermes Agent + Teknium, licence: MIT); merged from hermes/devops/claude-code-handoff (Hermes Agent, MIT).
Modified: translated in part; interactive tmux driving, dialog handling, permission-bypass recipes, local documentation paths of another project and installation steps removed.
Role: harness developer and orchestrator. Everything below is what the source skills state for Claude Code 2.x: check each flag against the pinned version (`claude --help`) before relying on it.

# `claude -p`, headless

## When
- Changing how the runner or the verifier starts a session or reads its stream.
- Launching a sub-agent lot from the host and reading what it did.

## What the sources state
Print mode: `claude -p "<task>"` runs one task and exits; no interactive dialog. Options named in the source:
- `--max-turns <n>`, `--allowedTools '<list>'`;
- `--output-format json`: one result object;
- `--output-format stream-json --verbose [--include-partial-messages]`: one JSON event per line;
- `--input-format stream-json --output-format stream-json --replay-user-messages`: streaming both ways;
- `--json-schema '<schema>'`: the validated object is in `structured_output` of the result;
- `--resume <session_id>`, `-c` (latest session of the directory), `-r "<id>"`;
- piped input: `<command> | claude -p "<question>"`.

Result object (`--output-format json`), fields named in the source: `type`, `subtype` (`success`,
`error_max_turns`, `error_budget`), `result`, `session_id`, `num_turns`, `total_cost_usd`, `duration_ms`,
`stop_reason`, `terminal_reason`, `usage`, `modelUsage`.

Stream: events include `system/api_retry` with `attempt`, `max_retries` and `error` (`rate_limit`,
`billing_error`).

Other subcommands named: `claude mcp add|list|remove`, `claude doctor`, `claude auth status`,
`claude setup-token`.

Transcripts: one JSONL file per session under the user's Claude directory, in a folder named after the
working directory. The size of the context at the last turn is `input_tokens + cache_creation_input_tokens
+ cache_read_input_tokens` of the last usage record. A transcript belongs to the machine that ran it.

Skills are discovered one level deep: `<skills dir>/<name>/SKILL.md`. Listed is not used: count the calls to
the `Skill` tool in the transcript.

## Do
1. Decide from `subtype` and `stop_reason`, never from the text of `result`. The runner already crosses the
   relay's log (status, message id, `stop_reason`) before believing a quota or a refusal: keep that.
2. Bound every launch: turns, minutes, and the relay's request budget for the segment.
3. Read a finished session from its transcript with a script, not by loading it into your own context:
   period, model, turns, compactions, tool histogram, `Skill` calls, last context size.
4. Keep the system prompt identical between agents, so it stays cached; what differs goes in the task.
5. A session of the agent or the judge loads only the MCP servers the harness configures
   (`--strict-mcp-config`), and a stray `.mcp.json` in the work directory is removed between segments.

## Never
- Disable permission checks to make a launch pass. Give an allowlist by command family.
- Rephrase and retry a refused task: a refusal closes the lead.
- Trust `Co-Authored-By` trailers to say who wrote a commit: read the author and committer fields.
- Treat the end of a transcript as the end of the work: commits may have landed after.

## Watch
- A nested `claude -p` inside the sandbox spends the same relay budget.
- More than about twenty visible tools switches on a tool-search beta the relay refuses: count them.
- Version drift: this skill is a pointer, the pinned version's help is the reference.
