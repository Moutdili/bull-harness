"""Recall server: a host thread alive during a segment that answers the sandbox's `bh-recall` requests.

Transport is files only (no socket): the agent writes `<BH_DIR>/recall/req/<id>.json`, this thread reads it every
TICK_S seconds, answers in `<BH_DIR>/recall/res/<id>.txt` (written to a temporary name, then renamed) and deletes the
request. It opens its own SQLite connection to the board; the sandbox only ever receives bounded text.

The work dir belongs to the sandbox, so everything in it is hostile: each directory below the trusted root is opened
with O_NOFOLLOW (a planted symlink sends no answer anywhere else on the host), a request must be a regular file of at
most REQ_MAX bytes (no FIFO that blocks the thread, no symlink to a host file), every field is checked for type and
length, and an error is one fixed line that echoes nothing of the request. No exception reaches the runner.
"""

from __future__ import annotations

import collections
import contextlib
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from pathlib import Path
from typing import Any

from bh import paths
from bh.lineage import recall

TICK_S = 0.5
REQ_MAX = 8 * 1024
PER_TICK = 10  # requests answered per tick: a flood waits, the thread never runs hot
STUCK_MAX = 10_000
RES_KEEP_S = 120.0  # an answer the client never collected is removed after this
ID_RE = re.compile(r"[A-Za-z0-9_-]{1,40}")
FIELDS = ("id", "mode", "query", "url", "class", "k", "arg")
MODES = ("search", *recall.MODES)
STR_MAX = {"query": recall.QUERY_MAX, "url": 2000, "class": 100, "arg": 500}
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class _Handle:
    """What bh.lineage.recall needs of a board: a `.db` connection."""

    def __init__(self, path: Path) -> None:
        self.db = sqlite3.connect(path, timeout=5)
        self.db.row_factory = sqlite3.Row


def validate(doc: object, stem: str) -> tuple[dict | None, str | None]:
    """(request, None) or (None, a fixed one-line reason). Nothing of the request is quoted back."""
    if not isinstance(doc, dict):
        return None, "request is not a JSON object"
    extra = set(doc) - set(FIELDS)
    if extra:
        return None, "unknown field in request"
    if doc.get("id") != stem:
        return None, "field id must match the file name"
    mode = doc.get("mode", "search")
    if mode not in MODES:
        return None, "field mode is not a known mode"
    out: dict[str, Any] = {"id": stem, "mode": mode}
    for f, n in STR_MAX.items():
        v = doc.get(f)
        if v is not None and not isinstance(v, str):
            return None, f"field {f} must be a string"
        if isinstance(v, str) and len(v) > n:
            return None, f"field {f} is longer than {n} characters"
        out[f] = v or None
    k = doc.get("k")
    if k is not None and (isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= recall.K_MAX):
        return None, f"field k must be an integer from 1 to {recall.K_MAX}"
    out["k"] = k or 10
    if mode == "search" and not (out["query"] or "").strip():
        return None, "a search needs a query"
    if mode in ("cell", "run", "full", "history") and not (out["arg"] or "").strip():
        return None, f"mode {mode} needs an argument"
    return out, None


class RecallServer:
    def __init__(
        self,
        program: str,
        run_id: int | None,
        board_path: str | Path,
        agent_no: int | None,
        *,
        root: Path | None = None,
        tick: float = TICK_S,
        say=None,
    ) -> None:
        self.program, self.run_id, self.agent_no = program, run_id, agent_no
        self.board_path = Path(board_path)
        # trusted root (host-owned): var/work; below it, program/.bh/recall belong to the sandbox
        self.root = Path(root) if root is not None else paths.var() / "work"
        self.parts = (program, ".bh", "recall")
        self.tick_s, self.say = tick, say
        self.served = self.errors = 0
        self.latency_ms: collections.deque[float] = collections.deque(maxlen=500)  # request mtime -> answer written
        self._handle: _Handle | None = None
        self._pruned = 0.0
        self._stuck: set[str] = set()  # answered requests the host could not delete: never answered twice
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- lifecycle
    def start(self) -> RecallServer:
        if self._thread is None:
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="bh-recall", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(5.0, 4 * self.tick_s))
            self._thread = None

    def _loop(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    self.poll()
                except Exception as exc:  # noqa: BLE001 (the recall informs, it never takes the segment down)
                    self.errors += 1
                    self._log(f"  ⚠ recall: {type(exc).__name__}")
                self._stop.wait(self.tick_s)
        finally:
            self._close()

    def _log(self, msg: str) -> None:
        if self.say:
            with contextlib.suppress(Exception):  # a broken logger is not a reason to stop answering
                self.say(msg)

    def _close(self) -> None:
        if self._handle is not None:
            with contextlib.suppress(sqlite3.Error):
                self._handle.db.close()
            self._handle = None

    # ---- files
    def _open_dir(self, *parts: str) -> int | None:
        """fd of root/parts, every part below the root opened without following a symlink; None if absent."""
        try:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return None
        try:
            for p in parts:
                nfd = os.open(p, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = nfd
        except OSError:
            os.close(fd)
            return None
        return fd

    def _res_dir(self) -> int | None:
        fd = self._open_dir(*self.parts, "res")
        if fd is not None:
            return fd
        base = self._open_dir(*self.parts)
        if base is None:
            return None
        try:
            os.mkdir("res", 0o755, dir_fd=base)
        except OSError:
            pass
        finally:
            os.close(base)
        return self._open_dir(*self.parts, "res")

    def _read(self, req: int, name: str) -> tuple[bytes | None, float]:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=req)
        except OSError:
            return None, 0.0
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > REQ_MAX:
                return None, st.st_mtime
            return os.read(fd, REQ_MAX + 1)[: REQ_MAX + 1], st.st_mtime
        finally:
            os.close(fd)

    @staticmethod
    def _write(res: int, stem: str, text: str) -> bool:
        tmp = f".{stem}.{secrets.token_hex(4)}.tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=res)
        except OSError:
            return False
        try:
            os.fchmod(fd, 0o644)
            data = (text.rstrip("\n") + "\n").encode("utf-8")
            while data:
                data = data[os.write(fd, data) :]
        except OSError:
            os.close(fd)
            _unlink(tmp, res)
            return False
        os.close(fd)
        try:
            os.replace(tmp, f"{stem}.txt", src_dir_fd=res, dst_dir_fd=res)
        except OSError:
            _unlink(tmp, res)
            return False
        return True

    def _prune(self, res: int, now: float) -> None:
        if now - self._pruned < 30:
            return
        self._pruned = now
        try:
            names = os.listdir(res)
        except OSError:
            return
        for n in names:
            if not n.endswith((".txt", ".tmp")):
                continue
            try:
                st = os.stat(n, dir_fd=res, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and now - st.st_mtime > RES_KEEP_S and st.st_uid == os.getuid():
                _unlink(n, res)

    # ---- one pass
    def poll(self) -> int:
        """Answer up to PER_TICK pending requests; returns how many were handled."""
        req = self._open_dir(*self.parts, "req")
        if req is None:
            return 0
        res = None
        try:
            try:
                names = sorted(
                    n for n in os.listdir(req) if n.endswith(".json") and not n.startswith(".") and n not in self._stuck
                )
            except OSError:
                return 0
            res = self._res_dir()
            if res is not None:
                self._prune(res, time.time())
            for name in names[:PER_TICK]:
                stem = name[: -len(".json")]
                raw, mtime = self._read(req, name)
                text = self.answer(raw, stem)
                if res is not None and ID_RE.fullmatch(stem) and self._write(res, stem, text):
                    self.served += 1
                    if mtime:
                        self.latency_ms.append(max(0.0, (time.time() - mtime) * 1000))
                if not _unlink(name, req) and len(self._stuck) < STUCK_MAX:
                    self._stuck.add(name)
            return min(len(names), PER_TICK)
        finally:
            os.close(req)
            if res is not None:
                os.close(res)

    def answer(self, raw: bytes | None, stem: str) -> str:
        """The text answer to one request file's bytes (an error is one line)."""
        if not ID_RE.fullmatch(stem):
            return "recall ERROR: bad request file name"
        if raw is None or len(raw) > REQ_MAX:
            return f"recall ERROR: request unreadable or larger than {REQ_MAX} bytes"
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return "recall ERROR: request is not JSON"
        r, err = validate(doc, stem)
        if err or r is None:
            return f"recall ERROR: {err}"
        try:
            if self._handle is None:
                self._handle = _Handle(self.board_path)
            if r["mode"] == "search":
                return recall.search(
                    self._handle,
                    self.program,
                    r["query"],
                    url=r["url"],
                    vuln_class=r["class"],
                    k=r["k"],
                    agent_no=self.agent_no,
                    run_id=self.run_id,
                )["text"]
            return recall.navigate(self._handle, self.program, r["mode"], r["arg"])
        except sqlite3.Error:
            self._close()
            return recall.UNAVAILABLE_LINE


def _unlink(name: str, dir_fd: int) -> bool:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        return False
    return True
