"""bh-web: drive the persistent headful browser (bh-browser) through its narrow API.

One browser, one live session (the identity the host loaded before the segment), kept across commands: a page
stays open between two calls. For targets behind a human challenge (Cloudflare Turnstile on Copilot): the operator
solves the challenge by hand in that same browser, never the agent. While a challenge is on screen the browser
refuses click/fill/press; `bh-web wait-human` polls until it is gone (the operator was pushed a notification).

    bh-web state                     url, title, identity, challenge pending?
    bh-web goto <url>                full navigation (on Copilot: a new app session, so a new challenge)
    bh-web fill <css> <text>         type into a field
    bh-web click <css>
    bh-web press <key>               Enter, Escape, Tab, ArrowDown, ...
    bh-web text                      visible text of the page (bounded, secrets redacted)
    bh-web wait <css|ms>             wait for a selector, or a number of milliseconds
    bh-web wait-human [--timeout S]  poll state() until no challenge is pending (default 480 s); rc 3 if still there

Stdlib only; the API is reached directly on the sandbox network (BH_BROWSER_URL, BH_BROWSER_TOKEN).
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

USAGE = __doc__.split("\n\n", 2)[2].split("\n\n")[0]
WAIT_HUMAN_S = 480  # below the Bash tool's 10 minute ceiling
POLL_S = 10


def _call(req: dict, timeout: float = 120) -> dict:
    url = os.environ.get("BH_BROWSER_URL", "http://browser:8790").rstrip("/") + "/op"
    token = os.environ.get("BH_BROWSER_TOKEN", "")
    if not token:
        return {"error": "bh-browser is not available in this sandbox (no BH_BROWSER_TOKEN)"}
    data = json.dumps(req).encode()
    r = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # same network, never via the gate
    try:
        with opener.open(r, timeout=timeout) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read() or b"{}") | {"status": e.code}
        except ValueError:
            return {"error": f"HTTP {e.code}", "status": e.code}
    except (OSError, ValueError) as e:
        return {"error": f"bh-browser unreachable: {type(e).__name__}"}


def request_for(argv: list[str]) -> dict | None:
    """The API request for a command line, None when it does not parse (pure: tested)."""
    if not argv:
        return None
    op, rest = argv[0], argv[1:]
    if op in ("state", "text") and not rest:
        return {"op": op}
    if op in ("goto", "click", "press") and len(rest) == 1:
        key = {"goto": "url", "click": "css", "press": "key"}[op]
        return {"op": op, key: rest[0]}
    if op == "fill" and len(rest) == 2:
        return {"op": "fill", "css": rest[0], "text": rest[1]}
    if op == "wait" and len(rest) == 1:
        return {"op": "wait", "ms": int(rest[0])} if rest[0].isdigit() else {"op": "wait", "css": rest[0]}
    return None


def _print(out: dict) -> int:
    if "text" in out and len(out) <= 2:
        print(out["text"])
        if out.get("truncated"):
            print("[truncated]")
        return 0
    print(json.dumps(out, ensure_ascii=False))
    if out.get("error") == "human-needed":
        print("a human challenge is on screen: run `bh-web wait-human`; never try to pass it yourself", file=sys.stderr)
        return 3
    return 1 if out.get("error") else 0


def wait_human(timeout: float, call=_call, sleep=time.sleep, clock=time.monotonic) -> int:
    end = clock() + timeout
    while True:
        st = call({"op": "state"}, 30)
        ch = st.get("challenge") or {}
        if st.get("error"):
            print(json.dumps(st))
            return 1
        if not ch.get("pending"):
            print(json.dumps({"challenge": "cleared", "url": st.get("url"), "human_done_at": st.get("human_done_at")}))
            return 0
        if clock() >= end:
            print(json.dumps({"challenge": "still pending", "since": ch.get("since")}))
            print(
                "not solved yet: `bh-note blocked captcha ...`, work on another surface, check `bh-web state` later",
                file=sys.stderr,
            )
            return 3
        sleep(POLL_S)


def main(argv: list[str]) -> None:
    if argv[:1] == ["wait-human"]:
        timeout = WAIT_HUMAN_S
        if len(argv) == 3 and argv[1] == "--timeout" and argv[2].isdigit():
            timeout = min(int(argv[2]), WAIT_HUMAN_S)
        elif len(argv) != 1:
            sys.exit(USAGE)
        sys.exit(wait_human(timeout))
    req = request_for(argv)
    if req is None:
        sys.exit(USAGE)
    sys.exit(_print(_call(req)))
