"""The host-planted canary (T24): a secret the attacker cannot know, in a field a human declared private.

The hunter's own canary (`bh-note canary`) proves little: it chose the token, so it knows it. Here the host draws it,
writes it once into the victim identity's private field, and keeps only its digest:

- the field is declared per target in the scope, on the identity that owns it (Mio's decision: any of our
  identities may be the victim, nothing fixes the roles):
      identities:
        - name: user-b
          private_field: {url: "https://app.example/api/me", method: PATCH, field: profile.bio}
  read as is from the identity's mapping (the scope's loader validates it). `field` is a JSON key, dotted for a
  nested one (`profile.bio` sends {"profile": {"bio": <canary>}}). `method` is PATCH (default), PUT or POST. A PUT
  sends that field alone: declare it only where the server merges. Nothing declared: nothing is planted.
- `plant(scope, name)`: one request through the gate under the victim's identity (`X-BH-Probe: 1` from the gate's
  own loopback, as the session probe: bh.gate.addon lends the session, keeps no body of it, the test objects'
  registry never looks at it), body {field: canary}. The canary is `BH-SECRET-<16 hex>`, the pattern the gate looks
  for everywhere. It travels on the gate script's stdin like a password and is then forgotten: the state file keeps
  `sha256` (bh.gate.canary.digest) and the location, never the token.
- the state: `var/state/identities/<program>/canary/<name>.json` (gate and host only, never mounted in the sandbox)
  = {"identity", "program", "sha256", "at": {url, method, field}, "ts"}.
- the hunter gets the location only (`canary_at`, the value of BH_CANARY_AT): where B's secret lives, so that A can
  try to read it. Its finding carries `token_sha256`; the host compares it with the digest of what the gate saw
  arrive on the attacker's side (bh.runner.observation). A canary the attacker sent itself is rejected there: the
  gate journals who sent it first.

A message, a return value or an exception never holds the canary.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

from bh import paths
from bh.accounts import enroll
from bh.gate import canary as gate_canary
from bh.scope import Scope

METHODS = ("PATCH", "PUT", "POST")
FIELD = re.compile(r"[A-Za-z0-9_$@-]{1,64}(\.[A-Za-z0-9_$@-]{1,64}){0,4}")
STATE_DIR = "canary"


class CanaryError(enroll.AccountError):
    """The plant failed. One line, never the canary."""


def declared(decl: dict[str, Any] | None) -> dict[str, str] | None:
    """The identity's `private_field` as {url, method, field}; None when it declares none. Raises CanaryError on a
    malformed declaration (a human fixes the scope: nothing is planted meanwhile)."""
    pf = (decl or {}).get("private_field")
    if pf is None:
        return None
    if not isinstance(pf, dict) or set(pf) - {"url", "method", "field"}:
        raise CanaryError("private_field: a mapping of url, method, field")
    url, field = pf.get("url"), pf.get("field")
    method = str(pf.get("method") or "PATCH").upper()
    if not isinstance(url, str) or not re.match(r"https?://[^/?#\s]+", url) or any(c in url for c in " \r\n"):
        raise CanaryError("private_field.url: an http(s) URL")
    if method not in METHODS:
        raise CanaryError(f"private_field.method: one of {', '.join(METHODS)}")
    if not isinstance(field, str) or not FIELD.fullmatch(field):
        raise CanaryError("private_field.field: a JSON key, dotted for a nested one (at most 5 levels)")
    return {"url": url, "method": method, "field": field}


def state_file(program: str, name: str) -> Path:
    return paths.identities_dir(program) / STATE_DIR / f"{name}.json"


def planted(program: str, name: str) -> dict[str, Any] | None:
    """What the host kept of the last canary planted for `name`: {identity, program, sha256, at, ts}, or None."""
    try:
        doc = json.loads(state_file(program, name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    ok = (
        isinstance(doc, dict)
        and isinstance(doc.get("sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", doc["sha256"])
        and isinstance(doc.get("at"), dict)
    )
    return doc if ok else None


def canary_at(scope: Scope) -> str:
    """BH_CANARY_AT for the hunter: JSON {identity: {url, method, field}} of the identities with a planted canary,
    "" when none. The location only: never the token, never its digest."""
    out = {}
    for ident in scope.identities:
        doc = planted(scope.program, ident["name"])
        if doc is not None:
            out[ident["name"]] = {k: doc["at"].get(k) for k in ("url", "method", "field")}
    return json.dumps(out, sort_keys=True, separators=(",", ":")) if out else ""


def _body(field: str, value: str) -> dict[str, Any]:
    body: dict[str, Any] = {}
    node = body
    *parents, last = field.split(".")
    for key in parents:
        node[key] = {}
        node = node[key]
    node[last] = value
    return body


def _save(path: Path, doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.stem}.", suffix=".tmp", dir=path.parent)  # 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def plant(scope: Scope, name: str, *, now: float | None = None) -> dict[str, Any]:
    """Draw a canary, write it once into `name`'s declared private field under its own identity (through the gate),
    keep its digest and location. Returns {identity, planted, ...}: `planted` False with `why` when the identity
    declares no private field (nothing sent). Raises CanaryError (no canary in it) when the plant fails."""
    ident = enroll.identity(scope, name)
    at = declared(ident.decl)
    if at is None:
        return {"identity": name, "planted": False, "why": "no private_field declared"}
    from bh.scope import check

    if not check(scope, at["url"]).allowed:
        raise CanaryError(f"{name}: private_field.url is not a target of {scope.program}")
    enroll.check_active(scope.program)
    if not ident.session_file.is_file():
        raise CanaryError(f"{name}: no session to plant with (log in first)")
    token = "BH-SECRET-" + os.urandom(8).hex()
    step = {
        "step": "plant",
        "method": at["method"],
        "url": at["url"],
        "headers": {"X-BH-Identity": name, "X-BH-Probe": "1"},
        "json": _body(at["field"], token),
    }
    try:
        rec = enroll.run_steps([step])[0]
    except enroll.AccountError as exc:
        raise CanaryError(str(exc).replace(token, "<canary>")) from None
    if rec.get("error") or rec.get("gate") or not 200 <= (rec.get("status") or 0) < 300:
        raise CanaryError(enroll._why(rec, f"{name}: plant").replace(token, "<canary>"))
    doc = {
        "identity": name,
        "program": scope.program,
        "sha256": gate_canary.digest(token),
        "at": at,
        "ts": round(time.time() if now is None else now, 3),
    }
    del token, step
    _save(state_file(scope.program, name), doc)
    return {**doc, "planted": True}
