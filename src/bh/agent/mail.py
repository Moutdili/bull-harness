"""bh-mail: read the recent mail of one of our test identities, served by the host (stdlib only).

  bh-mail <identity> [--since-min N]

The sandbox holds no mailbox token and reaches no mail server. This writes a request file in BH_DIR/mail/req/
({"id", "identity", "since_min"}), the host answers in BH_DIR/mail/res/ (bh.mailserve) and the answer is printed:
at most MESSAGES messages to that identity's address, received since the segment started (never earlier, whatever
--since-min), from a sender domain the program declares (`mail_from`), each between <mail-data-NONCE> tags. Codes
are masked, links outside the scope reduced to their host. No answer within WAIT_S seconds, no mailbox, an unknown
identity: `mail UNAVAILABLE`, exit 0. A mail read is supporting data: the finding keeps its proof.json or its
observation. bh-mail never sends anything.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from bh.agent import contract as c
from bh.agent import recall

WAIT_S = 8.0
UNAVAILABLE = "mail UNAVAILABLE"
SINCE_DEFAULT, SINCE_MAX = 60, 24 * 60  # minutes; the host never goes back past the segment's start anyway
IDENTITY_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
FIELDS = ("id", "identity", "since_min")


def base_dir() -> Path:
    return c.bh_dir() / "mail"


def parse(args: list[str]) -> dict:
    p = argparse.ArgumentParser(
        prog="bh-mail", description="Recent mail of one of our test identities, read by the host (see bh-mail -h)."
    )
    p.add_argument("identity", help="an identity of the program (user-a, user-b...)")
    p.add_argument("--since-min", type=int, default=SINCE_DEFAULT, help=f"minutes back, 1 to {SINCE_MAX}")
    a = p.parse_args(args)
    if not IDENTITY_RE.fullmatch(a.identity):
        p.error("the identity is a name of the program's identities (letters, digits, . _ -)")
    if not 1 <= a.since_min <= SINCE_MAX:
        p.error(f"--since-min is from 1 to {SINCE_MAX}")
    return {"identity": a.identity, "since_min": a.since_min}


def ask(request: dict, *, wait: float | None = None, base: Path | None = None) -> str | None:
    """Send one request, return the host's answer, or None when none came in time (the recall's file transport)."""
    return recall.ask(request, wait=WAIT_S if wait is None else wait, base=base or base_dir())


def main(args: list[str]) -> None:
    text = ask(parse(args))
    print((text or UNAVAILABLE).rstrip("\n"))
    sys.exit(0)
