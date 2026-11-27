"""CVSS 3.1 base score, computed by the host from a vector (plan item T28). The agent never writes a score.

Origin: strix/tools/reporting/tool.py, Strix (https://github.com/usestrix/strix), Copyright 2025 OmniSecure Inc.,
Apache License 2.0: `_CVSS_VALID` (the eight base metrics and their legal letters), `_calculate_cvss` (the vector
assembled from the eight metrics, the severity named from the score, "none" read as "info") and the calibration rules
of its report docstring (an H impact needs a demonstrated broad impact, S:C needs a crossing into another security
authority; kept in src/bh/skills/cvss-from-evidence).
Modified from Strix (Apache-2.0) by bull-harness: Strix delegates the arithmetic to the `cvss` package; here the base
equations, the weights and the Roundup function are written out from the public FIRST CVSS v3.1 specification
(section 7.1, 7.4 and Appendix A), with no dependency. Added: parsing of a vector string (the `CVSS:3.1/` prefix
optional, each base metric exactly once, nothing else), the comparison metric by metric that lets a judge lower a
vector and never raise it (`raised`), and the board columns (`ensure`).
"""

from __future__ import annotations

import math

PREFIX = "CVSS:3.1/"
METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
# legal letters of each base metric, the most severe first (the order `raised` compares on)
VALUES: dict[str, str] = {
    "AV": "NALP",
    "AC": "LH",
    "PR": "NLH",
    "UI": "NR",
    "S": "CU",
    "C": "HLN",
    "I": "HLN",
    "A": "HLN",
}
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}  # scope changed: a privilege weighs less
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"  # what a pipeline writes for anything (10.0)
COLUMNS = (("proof_level", "INTEGER"), ("cvss_vector", "TEXT"), ("cvss_score", "REAL"))


def parse(vector: str) -> dict[str, str]:
    """`CVSS:3.1/AV:N/...` or `AV:N/...` -> {"AV": "N", ...}. Raises ValueError for anything else: a missing or
    repeated metric, an unknown one (temporal and environmental metrics included), an illegal letter."""
    if not isinstance(vector, str) or len(vector) > 120:
        raise ValueError("a CVSS 3.1 vector is a string such as CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    text = vector.strip()
    if text.upper().startswith("CVSS:"):
        if not text.startswith(PREFIX):
            raise ValueError("only CVSS 3.1 vectors (CVSS:3.1/...)")
        text = text[len(PREFIX) :]
    out: dict[str, str] = {}
    for part in text.split("/"):
        name, sep, value = part.partition(":")
        if not sep or name not in VALUES:
            raise ValueError(f"unknown CVSS 3.1 base metric {part[:12]!r}")
        if name in out:
            raise ValueError(f"metric {name} given twice")
        if len(value) != 1 or value not in VALUES[name]:
            raise ValueError(f"{name}:{value[:4]} is not one of {'/'.join(VALUES[name])}")
        out[name] = value
    if missing := [m for m in METRICS if m not in out]:
        raise ValueError("missing metric(s): " + ", ".join(missing))
    return out


def normalize(vector: str) -> str:
    """The vector in the specification's order, with its `CVSS:3.1/` prefix."""
    m = parse(vector)
    return PREFIX + "/".join(f"{k}:{m[k]}" for k in METRICS)


def roundup(value: float) -> float:
    """The smallest number with one decimal that is >= value (FIRST CVSS v3.1, Appendix A: integer arithmetic, so
    4.000000000000001 gives 4.0 and not 4.1)."""
    n = round(value * 100_000)
    return n / 100_000.0 if n % 10_000 == 0 else (math.floor(n / 10_000) + 1) / 10.0


def score(vector: str) -> float:
    """The CVSS 3.1 base score of `vector` (0.0 to 10.0). Raises ValueError for a malformed vector."""
    m = parse(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    pr = (_PR_C if changed else _PR_U)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity(value: float) -> str:
    """The specification's rating of a score, in the names of bh.agent.contract.SEVERITIES (None -> info)."""
    s = float(value)
    if not 0.0 <= s <= 10.0:
        raise ValueError(f"a CVSS score is between 0.0 and 10.0, not {value}")
    if s == 0.0:
        return "info"
    return "low" if s < 4.0 else "medium" if s < 7.0 else "high" if s < 9.0 else "critical"


def raised(lower: str, than: str) -> list[str]:
    """The metrics of vector `lower` that are MORE severe than in vector `than` (empty: `lower` raises nothing).
    A judge's vector is refused when this is not empty. Raises ValueError for a malformed vector."""
    a, b = parse(lower), parse(than)
    return [k for k in METRICS if VALUES[k].index(a[k]) < VALUES[k].index(b[k])]


def ensure(board) -> None:
    """findings.proof_level (1 signal, 2 partial, 3 impact: bh.classes.PROOF_LEVELS), findings.cvss_vector (the
    normalized vector), findings.cvss_score (computed here). Idempotent."""
    have = {r["name"] for r in board.db.execute("PRAGMA table_info(findings)")}
    for col, typ in COLUMNS:
        if col not in have:
            board.db.execute(f"ALTER TABLE findings ADD COLUMN {col} {typ}")
    board.db.commit()
