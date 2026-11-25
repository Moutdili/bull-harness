"""Host side of a hunt with bh-browser: load an identity before a segment, and push a pending human challenge to
the operator (ntfy) while the segment runs, once per challenge.

The agent never notifies anyone and never touches the challenge (the controller refuses click/fill/press while one
is on screen); it runs `bh-web wait-human`, which only polls state(). The operator solves it in /captcha/.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from bh import stack

POLL_S = 10.0


def wanted(scope) -> bool:
    """A scope whose targets sit behind a third-party challenge (a `passthrough` support host) hunts with
    bh-browser: the operator solves the challenge there."""
    return bool(scope.support_hosts("passthrough"))


def prepare(scope, identities: list[str], say: Callable[[str], None] | None = None) -> str | None:
    """Before a segment: bh-browser up (never recreating the gate) and the first live identity's session loaded.
    Returns the identity loaded, None when bh-browser is not wanted or not available (said, never raised)."""
    from bh.browser_service import host as bhost

    say = say or (lambda m: None)
    if not wanted(scope):
        return None
    if not identities:
        say("bh-browser: no live identity to load; bh-web runs logged out")
        return None
    try:
        if not stack.container_running(stack.BROWSER_CTR):
            bhost.ensure_token()
            rc = stack.compose("--profile", stack.BROWSER_SERVICE, "up", "-d", "--no-deps", stack.BROWSER_SERVICE)
            if rc != 0 or not stack.container_running(stack.BROWSER_CTR):
                say("bh-browser: could not start it; bh-web is unavailable this segment")
                return None
        name = identities[0]
        req, _ = bhost.identity_payload(scope.program, name)
        out = bhost.call(req)
        if out.get("code") != 200:
            say(f"bh-browser: loading {name} failed: {out.get('error', 'no reply')}")
            return None
        say(f"bh-browser: {name} loaded ({out.get('cookies')} cookies); screen {bhost.view_url()}")
        return name
    except (SystemExit, OSError, ValueError) as exc:
        say(f"bh-browser: not prepared ({type(exc).__name__}: {str(exc)[:120]})")
        return None


class ChallengeWatcher:
    """Polls bh-browser's state every `interval` seconds while a segment runs; a challenge that appears is pushed
    once (keyed by its `since`). Never raises into the runner."""

    def __init__(
        self,
        interval: float = POLL_S,
        *,
        status: Callable[[], dict[str, Any]] | None = None,
        push: Callable[[str | None, str | None, str], None] | None = None,
        running: Callable[[], bool] | None = None,
        view: Callable[[], str] | None = None,
    ) -> None:
        from bh.browser_service import host as bhost
        from bh.browser_service import notify

        self.interval = interval
        self._status = status or (lambda: bhost.call({"op": "status"}, timeout=15))
        self._push = push or notify.captcha
        self._running = running or (lambda: stack.container_running(stack.BROWSER_CTR))
        self._view = view or bhost.view_url
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.notified: list[float] = []

    def tick(self) -> None:
        try:
            if not self._running():
                return
            out = self._status()
            ch = out.get("challenge") or {}
            since = ch.get("since")
            if ch.get("pending") and since is not None and since not in self.notified:
                self.notified.append(since)
                self._push(out.get("program"), out.get("identity"), self._view())
        except Exception:  # noqa: BLE001 - a watcher never breaks a hunt
            return

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self.tick()

    def start(self) -> ChallengeWatcher:
        """(Re)start polling; a challenge already pushed is never pushed again (one watcher a run, a thread a leg)."""
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="bh-challenge-watch", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval + 20)
