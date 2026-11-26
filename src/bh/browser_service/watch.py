"""Host side of a hunt with bh-browser: one identity per profile before a segment, the operator pushed a pending
human challenge (ntfy) while the segment runs, and the agent's `bh-web switch` requests carried out.

The agent never notifies anyone and never touches the challenge (the controller refuses click/fill/press/goto while
one is on screen); it runs `bh-web wait-human`, which only polls state(). The operator solves it in /captcha/.

Pushes: at most one every PUSH_MIN_S, a reminder REMIND_S after the first push when the same challenge is still on
screen, never more for that challenge. A failure (push, status, anything) is said once through `say`, never raised
into the runner.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from bh import stack

POLL_S = 10.0
PUSH_MIN_S = 300.0  # at most one push per 5 minutes
REMIND_S = 600.0  # a reminder 10 minutes after the first push of a challenge still there

# What the last prepare() loaded: the watcher's default program and list of live identities (for `switch`), and the
# scope (what the controller is told of it at every load: reload after a restart, switch).
PREPARED: dict[str, Any] = {"program": None, "identities": [], "scope": None}


def _scope_for(program: str | None):
    sc = PREPARED.get("scope")
    return sc if sc is not None and program is not None and getattr(sc, "program", None) == program else None


def wanted(scope) -> bool:
    """A scope whose targets sit behind a third-party challenge (a `passthrough` support host) hunts with
    bh-browser: the operator solves the challenge there."""
    return bool(scope.support_hosts("passthrough"))


def prepare(
    scope,
    identities: list[str],
    say: Callable[[str], None] | None = None,
    *,
    prompts: dict[str, int] | None = None,
    call: Callable[..., dict[str, Any]] | None = None,
    ensure_up: Callable[[], bool] | None = None,
) -> str | None:
    """Before a segment: bh-browser up (never recreating the gate), then one live identity in the profile.

    `prompts=None`: the profile keeps the identity it holds when that one is still live for this program (its
    challenge clearance survives); otherwise it is reset (forced: a stale challenge never outweighs mixing two
    accounts) and the first live identity loaded; the segment's budget is the full FILL_SEGMENT.

    `prompts` (identity -> prompts this run may type under it): the profile's identity is kept if it is served
    (more than 0); else the first served identity of `identities` is loaded (a reset: one more challenge, said);
    none served: the profile's identity is kept. Then the segment's budget is the loaded identity's share (0 allowed:
    the first fill is refused). The code never changes the identity during a segment.

    Returns the identity loaded, None when bh-browser is not wanted or not available (said, never raised)."""
    from bh.browser_service import host as bhost
    from bh.browser_service.controller import FILL_SEGMENT

    say = say or (lambda m: None)
    if not wanted(scope):
        return None
    PREPARED.update(program=scope.program, identities=list(identities), scope=scope)
    if not identities:
        say("bh-browser: no live identity to load; bh-web runs logged out")
        return None
    call = call or bhost.call
    try:
        if not (ensure_up or _ensure_up)():
            say("bh-browser: could not start it; bh-web is unavailable this segment")
            return None
        st = call({"op": "status"}, timeout=60)
        if st.get("code") != 200:
            say(f"bh-browser: no status ({st.get('error', 'no reply')}); not prepared")
            return None
        held = (st.get("program"), st.get("identity"))
        mine = held[1] if held[0] == scope.program and held[1] in identities else None
        name = mine or identities[0]
        if prompts is not None:
            served = [n for n in identities if int(prompts.get(n) or 0) > 0]
            if mine is not None and mine in served:
                name = mine
            elif served:
                name = served[0]
                if mine is not None:
                    say(
                        f"bh-browser: {mine} has no prompt left for this run, {name} has "
                        f"{int(prompts[name])}: the profile is wiped for it (one more human challenge for the operator)"
                    )
        if held != (scope.program, name):
            out = bhost.reset(scope.program, force=True, call_=call)
            if out.get("code") != 200:
                say(f"bh-browser: reset failed ({out.get('error', 'no reply')}); not prepared")
                return None
            if held[1] is not None:
                say(f"bh-browser: profile held {held[0]}/{held[1]}, wiped before {name}")
        out = bhost.load(scope.program, name, call_=call, scope=scope)
        if out.get("code") != 200:
            say(f"bh-browser: loading {name} failed: {out.get('error', 'no reply')} {out.get('detail', '')}".rstrip())
            return None
        if prompts is None:
            call({"op": "fill_budget_reset"}, timeout=30)
            share = ""
        else:
            budget = max(0, min(FILL_SEGMENT, int(prompts.get(name) or 0)))
            got = call({"op": "fill_budget_set", "segment": budget}, timeout=30)
            if got.get("code") not in (None, 200):
                say(f"bh-browser: the segment's prompt budget was not set ({got.get('error', 'no reply')})")
            share = f"; {budget} prompt(s) this segment"
        say(f"bh-browser: {name} loaded ({out.get('cookies')} cookies){share}; screen {bhost.view_url()}")
        return name
    except (SystemExit, OSError, ValueError) as exc:
        say(f"bh-browser: not prepared ({type(exc).__name__}: {str(exc)[:120]})")
        return None


def reload_marked(
    call: Callable[..., dict[str, Any]] | None = None, say: Callable[[str], None] | None = None
) -> str | None:
    """After bh-browser restarted (R36): the profile still names its identity (the marker) but the controller holds
    no session values (cookies_loaded 0, nothing to scrub with). Loads that same identity again, without a reset, and
    returns its name; None otherwise. Never another identity than the marker's; an unreadable marker ("?") reloads
    nothing. A failure is said, never raised."""
    from bh.browser_service import host as bhost
    from bh.browser_service.controller import NAME_RE

    call = call or bhost.call
    say = say or (lambda m: None)
    try:
        st = call({"op": "status"}, timeout=60)
        if st.get("code") not in (None, 200):
            return None
        program, name = st.get("program"), st.get("identity")
        if not (isinstance(program, str) and isinstance(name, str)):
            return None
        if not (NAME_RE.fullmatch(program) and NAME_RE.fullmatch(name)) or "?" in (program, name):
            return None
        if st.get("cookies_loaded") != 0:
            return None
        out = bhost.load(program, name, call_=call, scope=_scope_for(program))
    except (SystemExit, OSError, ValueError) as exc:
        say(f"bh-browser: reloading the marked identity failed ({type(exc).__name__}: {str(exc)[:120]})")
        return None
    if out.get("code") != 200:
        say(f"bh-browser: reloading {program}/{name} failed: {out.get('error', 'no reply')}")
        return None
    say(f"bh-browser: restarted; {program}/{name} reloaded from its profile marker ({out.get('cookies')} cookies)")
    return name


def _ensure_up() -> bool:
    from bh.browser_service import host as bhost

    if stack.container_running(stack.BROWSER_CTR):
        return True
    bhost.ensure_token()
    rc = stack.compose("--profile", stack.BROWSER_SERVICE, "up", "-d", "--no-deps", stack.BROWSER_SERVICE)
    return rc == 0 and stack.container_running(stack.BROWSER_CTR)


class ChallengeWatcher:
    """Polls bh-browser's status every `interval` seconds while a segment runs: pushes a pending challenge to the
    operator (bounded, one reminder) and carries out the agent's switch requests (live identities of the prepared
    program only). Never raises into the runner."""

    def __init__(
        self,
        interval: float = POLL_S,
        *,
        status: Callable[[], dict[str, Any]] | None = None,
        push: Callable[..., Any] | None = None,
        running: Callable[[], bool] | None = None,
        view: Callable[[], str] | None = None,
        program: str | None = None,
        identities: list[str] | None = None,
        say: Callable[[str], None] | None = None,
        call: Callable[..., dict[str, Any]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        from bh.browser_service import host as bhost
        from bh.browser_service import notify

        self.interval = interval
        self._call = call or bhost.call
        self._status = status or (lambda: self._call({"op": "status"}, timeout=15))
        self._push = push or notify.captcha
        self._running = running or (lambda: stack.container_running(stack.BROWSER_CTR))
        self._view = view or bhost.view_url
        self.program = program
        self.identities = identities
        self._say = say or (lambda m: None)
        self._clock = clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.pushes: dict[float, dict[str, Any]] = {}  # challenge `since` -> {first, reminded}
        self.last_push = float("-inf")
        self._told: set[str] = set()
        self._boots: set[Any] = set()  # bh-browser start times already handled (reload_marked once each)

    def _tell(self, key: str, msg: str) -> None:
        if key not in self._told:
            self._told.add(key)
            self._say(msg)

    # -- one poll
    def tick(self) -> None:
        try:
            if not self._running():
                return
            out = self._status()
            if out.get("code") not in (None, 200):
                self._tell("status", f"bh-browser watcher: no status ({out.get('error', 'no reply')}); said once")
                return
            self._reload(out)
            self._switch(out)
            self._challenge(out)
        except Exception as exc:  # noqa: BLE001 - a watcher never breaks a hunt, but it says why once
            self._tell("exc:" + type(exc).__name__, f"bh-browser watcher: {type(exc).__name__}: {str(exc)[:120]}")

    def _reload(self, out: dict[str, Any]) -> None:
        boot = out.get("boot")
        if boot is None or boot in self._boots:
            return
        self._boots.add(boot)
        reload_marked(call=self._call, say=lambda m: self._tell(f"reload:{boot}", m))

    def _challenge(self, out: dict[str, Any]) -> None:
        ch = out.get("challenge") or {}
        since = ch.get("since")
        if not ch.get("pending") or since is None:
            return
        now = self._clock()
        if now - self.last_push < PUSH_MIN_S:
            return
        rec = self.pushes.get(since)
        if rec is None:
            reminder = False
        elif not rec["reminded"] and now - rec["first"] >= REMIND_S:
            reminder = True
        else:
            return
        args = (out.get("program"), out.get("identity"), self._view())
        ok = self._push(*args, True) if reminder else self._push(*args)
        self.last_push = now
        if reminder:
            rec["reminded"] = True
        else:
            self.pushes[since] = {"first": now, "reminded": False}
        if ok is False:
            self._tell("push", "bh-browser watcher: the ntfy push failed (secrets/ntfy.env, network); said once")

    def _switch(self, out: dict[str, Any]) -> None:
        from bh.browser_service import host as bhost

        want = out.get("switch_requested")
        if not want:
            return
        if (out.get("challenge") or {}).get("pending"):  # a reset now would lose the challenge and the message
            self._tell("defer:" + want, f"bh-browser: switch to {want} waits until the challenge is solved")
            return
        program = self.program or PREPARED["program"]
        live = self.identities if self.identities is not None else PREPARED["identities"]
        if not program or want not in live or out.get("program") not in (None, program):
            reason = f"not a live identity of {program or 'the prepared program'}"
            self._call({"op": "switch_refused", "identity": want, "reason": reason}, timeout=30)
            self._say(f"bh-browser: switch to {want} refused ({reason})")
            return
        before = out.get("identity") if out.get("program") == program else None
        r = bhost.reset(program, call_=self._call)
        wiped = r.get("code") == 200
        if wiped:
            try:
                r = bhost.load(program, want, call_=self._call, scope=_scope_for(program))
            except SystemExit as exc:  # no session file
                r = {"code": 404, "error": str(exc)[:150]}
        if r.get("code") != 200:
            reason = str(r.get("error") or "failed")[:150]
            back = ""
            if wiped and before and before != "?":  # N13: never leave the browser logged out after a failed switch
                try:
                    b = bhost.load(program, before, call_=self._call, scope=_scope_for(program))
                except SystemExit as exc:
                    b = {"code": 404, "error": str(exc)[:150]}
                back = f"; {before} reloaded" if b.get("code") == 200 else f"; reloading {before} failed too"
            self._call({"op": "switch_refused", "identity": want, "reason": (reason + back)[:200]}, timeout=30)
            self._say(f"bh-browser: switch to {want} failed ({reason}){back}")
            return
        self._say(f"bh-browser: switched to {program}/{want} at the agent's request (a new challenge is likely)")

    # -- thread
    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self.tick()

    def start(self) -> ChallengeWatcher:
        """(Re)start polling; a challenge already pushed is not pushed again (one watcher a run, a thread a leg)."""
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="bh-challenge-watch", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval + 20)
