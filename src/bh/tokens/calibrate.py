"""TODO 2.5: what each candidate alias character costs in Claude's tokenizer, measured, not guessed.

Aliases are one character each, taken from ASCII letters and from the rest of Unicode (Greek, Cyrillic,
arrows, math, Arabic, Hebrew, CJK...), because the cheap names run out fast. A character is not one token by
default: measured where an alias stands (`cd /tmp; <ch> /rest/x`), an ASCII letter, the right arrow or Greek
alpha cost 1, Cyrillic zhe or Hebrew shin cost 2, a CJK ideograph 3, a Latin C with circumflex 5. Every
candidate is measured alone with `/v1/messages/count_tokens` through the gate's relay (the only holder of
the OAuth token), against the same line without it. Counting tokens costs no generation.

Excluded before measuring: digits and ASCII punctuation, characters that look like an ASCII letter or digit
(Cyrillic and Greek look-alikes, accented Latin: a wrong command waiting to happen), compatibility forms
(NFKC changes them), marks, spaces, controls, format and bidi controls, private use, unassigned.
"""

from __future__ import annotations

import json
import subprocess
import time
import unicodedata
from pathlib import Path

from bh import stack
from bh.runner.run import run_lock, set_active_run

TABLE = Path(__file__).with_name("symbols.json")
MODEL = "claude-sonnet-5-5"
MAX_REQUESTS = 5000

RANGES = {
    "ascii": (0x0041, 0x007A),
    "latin-ext": (0x00C0, 0x024F),
    "greek": (0x0370, 0x03FF),
    "cyrillic": (0x0400, 0x04FF),
    "armenian": (0x0531, 0x058A),
    "hebrew": (0x05D0, 0x05EA),
    "arabic": (0x0620, 0x064A),
    "devanagari": (0x0904, 0x0939),
    "thai": (0x0E01, 0x0E30),
    "georgian": (0x10D0, 0x10FA),
    "arrows": (0x2190, 0x21FF),
    "math": (0x2200, 0x22FF),
    "technical": (0x2300, 0x23FF),
    "box": (0x2500, 0x257F),
    "shapes": (0x25A0, 0x25FF),
    "misc-symbols": (0x2600, 0x26FF),
    "dingbats": (0x2700, 0x27BF),
    "hiragana": (0x3041, 0x3096),
    "katakana": (0x30A1, 0x30FA),
    "cjk": (0x4E00, 0x51FF),
    "hangul": (0xAC00, 0xAEFF),
}

# Characters that read as an ASCII letter or digit (a subset of Unicode confusables, enough for these ranges).
LOOKALIKES = set(
    "АВЕЅІЈКМНОРСТХУаеоріјсухѕԁԛԝһӏ"  # Cyrillic
    "ΑΒΕΖΗΙΚΜΝΟΡΤΥΧοιναρυκτχ"  # Greek
    "ÀÁÂÃÄÅàáâãäåÈÉÊËèéêëÌÍÎÏìíîïÒÓÔÕÖòóôõöÙÚÛÜùúûüÝýÿÇçÑñ"  # accented Latin: one stroke from ASCII
    "ǀǁǃ∣∕∖∗∘∙∪∨∧⁄‐‑−∼"  # bars, slashes, operators that pass for | / \\ * - ~
    "─━│┃"  # box lines that pass for - and |
    "ᅳ一丨丶丿乙"  # CJK strokes that pass for - | \\ /
)


def candidates() -> list[tuple[str, str]]:
    out = []
    for block, (lo, hi) in RANGES.items():
        for cp in range(lo, hi + 1):
            ch = chr(cp)
            cat = unicodedata.category(ch)
            if cat[0] in "MZC" or cat == "Lm" or ch in LOOKALIKES or (cp < 0x80 and not ch.isalpha()):
                continue
            if unicodedata.normalize("NFKC", ch) != ch or not unicodedata.name(ch, ""):
                continue
            out.append((ch, block))
    return out


# Runs inside the agent container (python3 -I, stdlib): POSTs count_tokens to the relay, reads stdin/writes stdout.
_WORKER = r"""
import json, sys, time, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor
job = json.load(sys.stdin)
CTX = job["context"]
def count(text):
    body = json.dumps({"model": job["model"], "messages": [{"role": "user", "content": text}]}).encode()
    req = urllib.request.Request("http://gate:8081/v1/messages/count_tokens", data=body, headers={
        "content-type": "application/json", "anthropic-version": "2023-06-01",
        "anthropic-beta": "oauth-2025-04-20", "authorization": "Bearer placeholder"})
    for attempt in range(6):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)["input_tokens"]
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 529):
                raise
            time.sleep(2 ** attempt)
    return None
base = count(CTX.format(""))
items = job["items"][: job["max_requests"] - 1]
with ThreadPoolExecutor(job["threads"]) as ex:
    counts = list(ex.map(lambda it: count(CTX.format(it + " ")), items))
result = {it: n - base for it, n in zip(items, counts) if n is not None}
json.dump({"result": result, "requests": len(items) + 1, "left": len(job["items"]) - len(result)}, sys.stdout)
"""


CONTEXT = "cd /tmp; {}/rest/x"  # where an alias stands: a command word after another command


def measure(items: list[str], *, model: str = MODEL, max_requests: int = MAX_REQUESTS, threads: int = 6) -> dict:
    """Cost of each item in command position, `{item: tokens}`, one count_tokens request each (plus a baseline)."""
    job = json.dumps(
        {"items": items, "model": model, "context": CONTEXT, "threads": threads, "max_requests": max_requests}
    )
    with run_lock():
        set_active_run(0, "tokenizer-calibration", relay_max=max_requests + 10)
        try:
            p = subprocess.run(
                ["podman", "exec", "-i", "--user", "hunter", stack.AGENT, "python3", "-I", "-c", _WORKER],
                input=job,
                capture_output=True,
                text=True,
                timeout=3 * 3600,
            )
        finally:
            set_active_run(None)
    if p.returncode:
        raise SystemExit(f"calibration failed: {p.stderr.strip()[-400:]}")
    return json.loads(p.stdout)


def measure_strings(items: list[str], *, model: str = MODEL) -> dict[str, int]:
    """Exact token cost of each string in command position (used by the miner for prefixes)."""
    return measure(items, model=model, max_requests=len(items) + 2)["result"]


def calibrate(*, model: str = MODEL) -> dict:
    cands = candidates()
    probe = measure(["q", "qq"], model=model, max_requests=4)["result"]  # the method, checked on known costs
    if probe != {"q": 1, "qq": 2}:
        raise SystemExit(f"calibration method is off: {probe}")
    m = measure([ch for ch, _ in cands], model=model, max_requests=len(cands) + 2)
    block = dict(cands)
    costs = m["result"]
    table = {
        "model": model,
        "measured": time.strftime("%Y-%m-%d"),
        "context": CONTEXT,
        "requests": m["requests"],
        "unmeasured": m["left"],
        "candidates": len(cands),
        "by_cost": {str(k): sum(1 for v in costs.values() if v == k) for k in sorted(set(costs.values()))},
        "one_token_by_block": {
            b: sum(1 for ch, v in costs.items() if v == 1 and block[ch] == b)
            for b in RANGES
            if any(v == 1 and block[ch] == b for ch, v in costs.items())
        },
        "costs": dict(sorted(costs.items(), key=lambda kv: (kv[1], kv[0]))),
    }
    TABLE.write_text(json.dumps(table, ensure_ascii=False, indent=1) + "\n")
    return table
