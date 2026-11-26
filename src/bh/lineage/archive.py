"""Archive of an agent's trace (D11): `var/lineage/<program>/<no>-<pseudo-slug>/`.

Host side only: no compose volume mounts `var/lineage` (a test reads container/compose.yaml), and the sandbox never
reads the host's archives. Everything copied here goes through bh.redact, the one definition of "sensitive": the
identity card (keys that name a credential become placeholders), the system prompt and the task (free text), the
`claude -p` stream and the hook log (JSON lines: sensitive keys replaced and every string treated as free text;
other lines as free text). `manifest.json` lists the sha256 of each file written.

The directory name never carries the pseudo as written: `slug()` keeps ASCII lowercase letters and digits joined by
hyphens (`0142-zero-plague-ii`). Retention keeps this tree (cold tier, bh.retention).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

from bh import paths, redact

LINEAGE_DIR = "lineage"
MANIFEST = "manifest.json"
_PROGRAM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def root() -> Path:
    return paths.var() / LINEAGE_DIR


def slug(pseudo: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", pseudo.encode("ascii", "ignore").decode().lower()).strip("-") or "agent"


def agent_dir(program: str, no: int, pseudo: str) -> Path:
    if not _PROGRAM_RE.match(program or "") or ".." in program:
        raise ValueError(f"bad program name {program!r}")
    return root() / program / f"{int(no):04d}-{slug(pseudo)}"


def _sensitive(key) -> bool:
    k = str(key)
    return bool(redact.SENSITIVE_KEY.search(k) or redact.SENSITIVE_HEADER.match(k))


def scrub(obj):
    """JSON value with bh.redact applied: a key bh.redact names as a credential (key or header name, so `cookie` too)
    becomes a placeholder, every string is redacted as free text (header lines, key=value pairs, JWTs)."""
    if isinstance(obj, dict):
        return {k: redact.placeholder(str(k).lower()) if _sensitive(k) else scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    if isinstance(obj, str):
        return redact.text(obj)
    return obj


def _scrub_lines(src: Path):
    with open(src, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            raw = line.rstrip("\n")
            try:
                doc = json.loads(raw)
            except ValueError:
                yield redact.text(raw)
                continue
            yield json.dumps(scrub(doc), ensure_ascii=False) if isinstance(doc, (dict, list)) else redact.text(raw)


def _put(path: Path, text: str) -> str:
    data = text.encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return hashlib.sha256(data).hexdigest()


def write(
    dir: Path,
    *,
    identity: dict,
    system_prompt: str,
    task: str,
    stream_path: str | Path | None,
    hooks_path: str | Path | None,
) -> Path:
    """Write the redacted archive into `dir`; return the manifest's path. A missing stream or hook log is noted in
    the manifest (`absent`), not invented."""
    d = Path(dir)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    files: dict[str, str] = {}
    absent: list[str] = []
    files["identity.json"] = _put(
        d / "identity.json", json.dumps(scrub(identity), sort_keys=True, indent=1, ensure_ascii=False) + "\n"
    )
    files["system_prompt.txt"] = _put(d / "system_prompt.txt", redact.text(system_prompt or ""))
    files["task.txt"] = _put(d / "task.txt", redact.text(task or ""))
    for name, src in (("stream.jsonl", stream_path), ("hooks.jsonl", hooks_path)):
        if src is None or not Path(src).is_file():
            absent.append(name)
            continue
        files[name] = _put(d / name, "".join(line + "\n" for line in _scrub_lines(Path(src))))
    manifest = {"files": files, "absent": absent, "written": time.time(), "redacted_by": "bh.redact"}
    out = d / MANIFEST
    _put(out, json.dumps(manifest, sort_keys=True, indent=1) + "\n")
    return out
