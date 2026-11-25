"""Push "a human challenge waits for Mio" to his phone through ntfy (docs/research/18).

The topic lives in `secrets/ntfy.env` (`BH_NTFY_TOPIC=<random>`, 0600, host only): on ntfy.sh, whoever knows a topic
name can read it, so the name is the secret. The message carries no credential and no target content: the program,
the identity name and the link to the UI's /captcha/ page (a Tailscale address, useless off the tailnet).
"""

from __future__ import annotations

import os
import secrets as _rand
import urllib.request

from bh import paths

SERVER = "https://ntfy.sh"
TOPIC_ENV = "BH_NTFY_TOPIC"


def env_path():
    return paths.secrets_dir() / "ntfy.env"


def topic(create: bool = False) -> str | None:
    """The topic name; with `create`, a new random one is written when there is none."""
    p = env_path()
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            k, _, v = line.partition("=")
            if k.strip() == TOPIC_ENV and len(v.strip()) >= 20:
                return v.strip()
    except OSError:
        pass
    if not create:
        return None
    t = "bh-" + _rand.token_urlsafe(24).replace("_", "x").replace("-", "y")
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"{TOPIC_ENV}={t}\n")
    return t


def send(title: str, message: str, click: str | None = None, priority: str = "high", timeout: float = 10) -> bool:
    """One push; False (never an exception) when there is no topic or ntfy is unreachable."""
    t = topic()
    if not t:
        return False
    headers = {"Title": title.encode("ascii", "replace").decode(), "Priority": priority, "Tags": "robot"}
    if click:
        headers["Click"] = click
    req = urllib.request.Request(f"{SERVER}/{t}", data=message.encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300
    except OSError:
        return False


def captcha(program: str | None, identity: str | None, url: str) -> None:
    """Tell the operator that `program`/`identity` waits on a human challenge, to be solved at `url`."""
    who = "/".join(x for x in (program, identity) if x) or "bh-browser"
    send("bull-harness: captcha a faire", f"{who} attend un challenge humain. Ouvre l'ecran et resous-le.", url)
