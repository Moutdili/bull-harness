"""Number and pseudo of an agent (D8): `#0142 Zero Plague`.

An agent is one `claude -p` session with a fresh context. Its number is a global counter, never reused; its pseudo
is drawn from two fixed tables of famous handles, recombined so that no original handle comes out:
- `h = sha256(seed + str(no))`, head = `int(h[0:4], 16) mod 21`, tail = `int(h[4:8], 16) mod 26`;
- a forbidden pair (an original handle) takes the next tail, as many times as needed (Dark Dante -> Dark Tangent
  -> Dark Oblivion);
- a pair some agent already wears takes a roman numeral: `Zero Plague II`, `Zero Plague III`...

The pseudo is a label for humans and for the board. It is never a path (bh.lineage.archive.slug), never a header,
never a User-Agent, and no text describes a character behind it: the prompt says "registered as", not "you are".

TABLES_SHA256 pins the tables and the forbidden pairs: it goes into every setup (`pseudo_rule`), so an agent can be
relaunched under the same naming rule, and a test fails if the tables move. The tables are validated: do not edit.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

HEADS = (
    "Captain",
    "Phiber",
    "Acid",
    "Zero",
    "Crash",
    "Cereal",
    "Lord",
    "Dark",
    "Space",
    "Weld",
    "Brian",
    "Solar",
    "Aleph",
    "Knight",
    "Taran",
    "Erik",
    "Lex",
    "Susy",
    "Halvar",
    "Mister",
    "Professor",
)
TAILS = (
    "Crunch",
    "Optik",
    "Burn",
    "Cool",
    "Override",
    "Nikon",
    "Plague",
    "Dante",
    "Tangent",
    "Rogue",
    "Pond",
    "Oblivion",
    "Kingpin",
    "Mudge",
    "Designer",
    "One",
    "Lightning",
    "King",
    "Bloodaxe",
    "Luthor",
    "Thunder",
    "Mentor",
    "Condor",
    "Flake",
    "Robot",
    "Falken",
)
# the original handles: never drawn
FORBIDDEN = frozenset(
    {
        ("Captain", "Crunch"),
        ("Phiber", "Optik"),
        ("Acid", "Burn"),
        ("Zero", "Cool"),
        ("Crash", "Override"),
        ("Lord", "Nikon"),
        ("Dark", "Dante"),
        ("Dark", "Tangent"),
        ("Space", "Rogue"),
        ("Weld", "Pond"),
        ("Brian", "Oblivion"),
        ("Solar", "Designer"),
        ("Aleph", "One"),
        ("Knight", "Lightning"),
        ("Taran", "King"),
        ("Erik", "Bloodaxe"),
        ("Lex", "Luthor"),
        ("Susy", "Thunder"),
        ("Halvar", "Flake"),
        ("Mister", "Robot"),
        ("Professor", "Falken"),
    }
)


def _tables_sha256() -> str:
    doc = {"heads": list(HEADS), "tails": list(TAILS), "forbidden": sorted(" ".join(p) for p in FORBIDDEN)}
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


TABLES_SHA256 = _tables_sha256()


def label(no: int) -> str:
    """The number as shown: `#0142`."""
    return f"#{int(no):04d}"


def pair(head: int, tail: int) -> str:
    """The pair at (head, tail) indices, after the forbidden-pair rule (next tail until the pair is not an original
    handle). Every head has at least one allowed tail, so this ends."""
    h = HEADS[head % len(HEADS)]
    t = tail % len(TAILS)
    while (h, TAILS[t]) in FORBIDDEN:
        t = (t + 1) % len(TAILS)
    return f"{h} {TAILS[t]}"


_ROMAN = ((1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"), (90, "XC"), (50, "L"), (40, "XL"),
          (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I"))  # fmt: skip


def roman(n: int) -> str:
    out = []
    for value, sym in _ROMAN:
        while n >= value:
            out.append(sym)
            n -= value
    return "".join(out)


def pseudo(no: int, seed: str, taken: Iterable[str] = ()) -> str:
    """Pseudo of agent `no`. `taken`: the pseudos already worn (the `agents` table); the first free form among
    `<pair>`, `<pair> II`, `<pair> III`... is returned. Same inputs, same output."""
    h = hashlib.sha256(f"{seed}{int(no)}".encode()).hexdigest()
    base = pair(int(h[0:4], 16) % len(HEADS), int(h[4:8], 16) % len(TAILS))
    worn = set(taken)
    if base not in worn:
        return base
    n = 2
    while f"{base} {roman(n)}" in worn:
        n += 1
    return f"{base} {roman(n)}"
