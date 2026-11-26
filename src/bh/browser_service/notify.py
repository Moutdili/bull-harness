"""Push "a human challenge waits for Mio" to his phone through ntfy (docs/research/18).

The topic lives in `secrets/ntfy.env` (`BH_NTFY_TOPIC=<random>`, 0600, host only): on ntfy.sh, whoever knows a topic
name can read it and post to it, so the name is the secret. `rotate()` replaces a topic that leaked. The message
carries no credential and no target content: the program, the identity name and the link to the UI's /captcha/
page (a Tailscale address, useless off the tailnet).
"""

from __future__ import annotations

import os
import secrets as _rand
import sys
import urllib.request

from bh import paths

SERVER = "https://ntfy.sh"
TOPIC_ENV = "BH_NTFY_TOPIC"
_told: set[str] = set()  # failures already said (once each, on stderr)


def _say_once(key: str, msg: str) -> None:
    if key not in _told:
        _told.add(key)
        print(f"ntfy: {msg}", file=sys.stderr, flush=True)


def env_path():
    return paths.secrets_dir() / "ntfy.env"


def _new_topic() -> str:
    return "bh-" + _rand.token_urlsafe(24).replace("_", "x").replace("-", "y")


def _write(t: str) -> None:
    """Atomic: a temporary 0600 file next to it, then a rename over the old one."""
    p = env_path()
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"{TOPIC_ENV}={t}\n")
    os.replace(tmp, p)


def topic(create: bool = False) -> str | None:
    """The topic name; with `create`, a new random one is written when there is none."""
    try:
        for line in env_path().read_text(encoding="utf-8").splitlines():
            k, _, v = line.partition("=")
            if k.strip() == TOPIC_ENV and len(v.strip()) >= 20:
                return v.strip()
    except FileNotFoundError:
        pass
    except OSError as exc:
        _say_once("read", f"cannot read {env_path()}: {type(exc).__name__}")
    if not create:
        return None
    t = _new_topic()
    _write(t)
    return t


def rotate() -> str:
    """A new random topic replaces the old one (which then receives nothing of ours). The phone subscribes to the
    new name; returns it."""
    t = _new_topic()
    _write(t)
    return t


def send(title: str, message: str, click: str | None = None, priority: str = "high", timeout: float = 10) -> bool:
    """One push; False (never an exception) when there is no topic or ntfy is unreachable (said once on stderr)."""
    t = topic()
    if not t:
        _say_once("topic", f"no topic in {env_path()}: nothing is pushed")
        return False
    headers = {"Title": title.encode("ascii", "replace").decode(), "Priority": priority, "Tags": "robot"}
    if click:
        headers["Click"] = click
    req = urllib.request.Request(f"{SERVER}/{t}", data=message.encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ok = 200 <= r.status < 300
    except OSError as exc:
        _say_once("send", f"push failed ({type(exc).__name__}); later failures are not repeated")
        return False
    if not ok:
        _say_once("status", "push refused by the server; later refusals are not repeated")
    return ok


def captcha(program: str | None, identity: str | None, url: str, reminder: bool = False) -> bool:
    """Tell the operator that `program`/`identity` waits on a human challenge, to be solved at `url`. True when the
    push went out."""
    who = "/".join(x for x in (program, identity) if x) or "bh-browser"
    title = "bull-harness: captcha toujours en attente" if reminder else "bull-harness: captcha a faire"
    return send(title, f"{who} attend un challenge humain. Ouvre l'ecran et resous-le.", url)
