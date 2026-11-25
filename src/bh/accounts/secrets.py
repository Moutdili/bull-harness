"""Credentials of the harness's own test accounts: `secrets/identities/<program>/<name>.json` on the host.

{"email": "...", "password": "...", "answer": "...", "created": 1764000000.0}

Directories 0700, files 0600, written atomically. Never mounted in a container: the gate gets a credential only
on the stdin of one enrollment script, the agent never.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets as _rand
import tempfile
import time
from pathlib import Path
from typing import Any

from bh import paths

FIELDS = ("email", "password", "answer")


def path(program: str, name: str) -> Path:
    return paths.secrets_dir() / "identities" / program / f"{name}.json"


def _private_dir(d: Path) -> None:
    """`d` and the parents up to secrets/ exist, owner-only."""
    root = paths.secrets_dir()
    for p in [*reversed(d.relative_to(root).parents), d.relative_to(root)]:
        full = root / p
        full.mkdir(mode=0o700, parents=True, exist_ok=True)
        if full != root:
            os.chmod(full, 0o700)


def load(program: str, name: str) -> dict[str, Any] | None:
    """The stored credential, None when there is none or it is unreadable (never an error that quotes it)."""
    p = path(program, name)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or not all(isinstance(doc.get(k), str) and doc[k] for k in ("email", "password")):
        return None
    return doc


def save(program: str, name: str, cred: dict[str, Any]) -> Path:
    p = path(program, name)
    _private_dir(p.parent)
    fd, tmp = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=p.parent)  # 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cred, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return p


def new(email_template: str, name: str) -> dict[str, Any]:
    """A fresh credential: the address from the recipe's template, a random password and security answer."""
    from bh.accounts.recipe import render

    return {
        "email": render(email_template, {"name": name, "rand": _rand.token_hex(3)}),
        "password": _rand.token_urlsafe(18),
        "answer": _rand.token_hex(6),
        "created": round(time.time(), 3),
    }
