"""TODO 2.4: mine the agent's commands for prefixes worth a one-character alias, with the net saving in figures.

Source: the Bash commands of every run log (`var/runs/*.jsonl`). Each command is cut into simple commands
(`;`, `&&`, `||`, `|`, newlines); every literal word prefix of 1 to 4 words is a candidate (`bh-note frontier`,
`q -a user-a`). Prefixes with a quote, `$`, a glob or a URL are not literal enough to alias.

Net saving of an alias, per segment, in input-token equivalents (Sonnet prices: output 5x input, cache read
0.1x, 1-hour cache write 2x):
  gain   = uses * (tokens(prefix) - 1) * (5 + 0.1 * T/2)   written once as output, then read on ~T/2 turns
  legend = tokens(legend line) * (2 + 0.1 * T)              written once in the cache, read on every turn
where `uses` is per segment and T the turns of a segment. An alias is kept only if gain > legend.
A longer prefix takes its uses away from the shorter ones it contains (`bh-note fact` from `bh-note`).
"""

from __future__ import annotations

import json
import re
import shlex
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from bh import paths

OUTPUT_X, CACHE_READ_X, CACHE_WRITE_X = 5.0, 0.1, 2.0
SEGMENT_TURNS = 50
MIN_USES = 3
MAX_WORDS = 4
SHELL_WORDS = {
    "for", "do", "done", "if", "then", "else", "elif", "fi", "while", "until", "case", "esac", "in", "{", "}", "!"
}  # fmt: skip
# An alias is an executable: it cannot change the calling shell (cwd, variables, options), so builtins are out.
BUILTINS = {
    "cd",
    "export",
    "source",
    ".",
    "alias",
    "unalias",
    "set",
    "unset",
    "exit",
    "eval",
    "exec",
    "read",
    "ulimit",
    "umask",
    "pushd",
    "popd",
    "shopt",
    "trap",
    "return",
    "local",
    "declare",
    "typeset",
    "wait",
}
_LITERAL = re.compile(r"^[A-Za-z0-9_./:=,+@%-]+$")


@dataclass
class Candidate:
    prefix: str
    count: int  # simple commands starting with it, over all runs
    tokens: int = 0  # measured cost of the prefix
    uses: float = 0.0  # per segment, after longer chosen aliases took theirs
    net: float = 0.0  # saving per segment, input-token equivalents


def commands(runs_dir: Path | None = None) -> tuple[list[str], int]:
    """Every Bash command of every run log, and the number of runs that had at least one."""
    out, runs = [], 0
    for f in sorted((runs_dir or paths.runs_dir()).glob("*.jsonl")):
        n = len(out)
        for line in f.read_text(errors="replace").splitlines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("type") != "assistant":
                continue
            for b in (ev.get("message") or {}).get("content") or []:
                if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == "Bash":
                    cmd = (b.get("input") or {}).get("command")
                    if isinstance(cmd, str):
                        out.append(cmd)
        runs += len(out) > n
    return out, runs


_HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1([^\n]*)\n.*?(?:\n[ \t]*\2[ \t]*(?=\n|$)|$)", re.S)
_SEPARATORS = {";", "&", "&&", "|", "||", "\n", "(", ")", ";;", "|&", "&;"}


def simple_commands(cmd: str) -> list[list[str]]:
    """The words of each simple command in `cmd`. Heredoc bodies are dropped and quoted text stays one word, so a
    `;`, `|` or newline inside a note or a script never starts a fake command."""
    cmd = _HEREDOC.sub(lambda m: m.group(3) + "\n", cmd)
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        tokens = list(lex)
    except ValueError:  # unbalanced quote: plain split, the old way
        return [part.split() for part in re.split(r"\n|;|&&|\|\||\|", cmd)]
    out: list[list[str]] = [[]]
    functions = set()  # `b(){ ...; }` then `b x`: a shell function, not something an executable can stand for
    for tok in tokens:
        if tok == "()" and len(out[-1]) == 1:
            functions.add(out[-1].pop())
        if tok in _SEPARATORS or (tok and set(tok) <= set(";&|\n()")):
            out.append([])
        else:
            out[-1].append(tok)
    return [w for w in out if w and w[0] not in functions]


def prefixes(cmd: str) -> list[str]:
    """Literal word prefixes (1..MAX_WORDS words) of each simple command in `cmd`."""
    found = []
    for simple in simple_commands(cmd):
        lead = 0  # `do curl ...`, `then echo ...`: the command starts after the keywords
        while lead < len(simple) and simple[lead] in SHELL_WORDS - {"for", "case", "in"}:
            lead += 1
        words = simple[lead:]
        if not words or words[0] in SHELL_WORDS | BUILTINS or "=" in words[0]:
            continue
        for k in range(1, min(MAX_WORDS, len(words)) + 1):
            w = words[k - 1]
            if not _LITERAL.match(w) or "://" in w or len(w) > 40:
                break
            found.append(" ".join(words[:k]))
    return found


def count_prefixes(cmds: list[str]) -> Counter:
    c: Counter = Counter()
    for cmd in cmds:
        c.update(prefixes(cmd))
    return c


def legend_line(symbol: str, prefix: str) -> str:
    return f"{symbol} = {prefix}\n"


def net_saving(tokens: int, uses: float, symbol: int = 1, turns: int = SEGMENT_TURNS) -> float:
    """Per segment, input-token equivalents: what typing the symbol instead of the prefix saves, minus the
    legend line (`<symbol> = <prefix>`, about symbol + prefix + 2 tokens) that every turn re-reads."""
    gain = uses * (tokens - symbol) * (OUTPUT_X + CACHE_READ_X * turns / 2)
    cost = (tokens + symbol + 2) * (CACHE_WRITE_X + CACHE_READ_X * turns)
    return gain - cost


def select(
    cands: list[Candidate], runs: int, symbol_costs: list[int] | None = None, *, turns: int = SEGMENT_TURNS
) -> list[Candidate]:
    """Greedy, best marginal net saving first; the i-th alias gets the i-th cheapest symbol.
    Both directions of overlap count: a chosen `bh-note fact` takes its uses away from `bh-note`, and a chosen
    `bh-note` already saves part of `bh-note fact`, which is then priced on what it saves on top."""
    costs = list(symbol_costs) if symbol_costs is not None else [1] * 1000
    left = {c.prefix: float(c.count) for c in cands}
    saved: dict[str, int] = {}  # chosen prefix -> tokens its alias saves per use
    chosen: list[Candidate] = []

    def already(c: Candidate) -> int:
        words = c.prefix.split(" ")
        return max((saved.get(" ".join(words[:k]), 0) for k in range(1, len(words))), default=0)

    while len(chosen) < len(costs):
        sym = costs[len(chosen)]
        best = None
        for c in cands:
            eff = c.tokens - already(c)  # what this alias would still save, plus the symbol it costs
            if c in chosen or eff <= sym:
                continue
            c.uses = left[c.prefix] / max(1, runs)
            c.net = c.uses * (eff - sym) * (OUTPUT_X + CACHE_READ_X * turns / 2) - (c.tokens + sym + 2) * (
                CACHE_WRITE_X + CACHE_READ_X * turns
            )
            if left[c.prefix] >= MIN_USES and c.net > 0 and (best is None or c.net > best.net):
                best = c
        if best is None:
            break
        chosen.append(best)
        saved[best.prefix] = best.tokens - costs[len(chosen) - 1]
        words = best.prefix.split(" ")
        for k in range(1, len(words)):
            shorter = " ".join(words[:k])
            if shorter in left:
                left[shorter] = max(0.0, left[shorter] - left[best.prefix])
    return chosen


def mine(
    *, runs_dir: Path | None = None, turns: int = SEGMENT_TURNS, symbol_costs: list[int] | None = None, measure=None
) -> tuple[list[Candidate], int]:
    """Prefixes worth an alias, best first, and the number of runs mined. `measure(list[str]) -> {str: tokens}`
    defaults to the exact count through the relay (bh.tokens.calibrate)."""
    cmds, runs = commands(runs_dir)
    counts = count_prefixes(cmds)
    cands = [Candidate(p, n) for p, n in counts.items() if n >= MIN_USES]
    if not cands:
        return [], runs
    if measure is None:
        from bh.tokens.calibrate import measure_strings as measure
    costs = measure([c.prefix for c in cands])
    for c in cands:
        c.tokens = int(costs.get(c.prefix, 0))
    return select(cands, runs, symbol_costs, turns=turns), runs
