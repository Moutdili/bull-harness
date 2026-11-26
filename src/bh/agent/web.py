"""bh-web: drive the persistent headful browser (bh-browser) through its narrow API.

One browser, one live session (the identity the host loaded before the segment), kept across commands: a page
stays open between two calls. For targets behind a human challenge (Cloudflare Turnstile on Copilot): the operator
solves the challenge by hand in that same browser, never the agent. While a challenge is on screen the browser
refuses click/fill/press/goto/upload; `bh-web wait-human` polls until it is gone (the operator was pushed a
notification). While the operator has the screen open, only state, text and frames are answered.

    bh-web state                       url, title, identity, challenge, tabs, fill budget left
    bh-web goto <url>                  full navigation (on Copilot: a new app session, so a new challenge)
    bh-web fill <css> <text>           type into a field (a prompt: 80 a segment, 200 a day per identity)
    bh-web click <css>
    bh-web press <key>                 Enter, Escape, Tab, ArrowDown, ...
    bh-web text [--css C] [--tail N]   visible text (head, or the last N characters: a chat's last answer)
    bh-web outline [--css C]           accessibility tree of the page (roles, names): the controls to act on
    bh-web attr <css> <name>           one attribute (href of a share link, value, aria-*)
    bh-web net [--last N] [--denied]   recent requests: method, redacted URL, status, gate refusals
    bh-web frames [--last N]           recent websocket frames (redacted; challenge answers never kept)
    bh-web tabs [--select I]           list the open tabs, or drive tab I (a popup never takes over by itself)
    bh-web upload <css> <file>         set a file input (at most 256 KiB), without opening a file picker
    bh-web switch <identity>           ask the host for another live identity (profile wiped: a new challenge)
    bh-web wait <css|ms>               wait for a selector, or a number of milliseconds
    bh-web wait-human [--timeout S]    poll state() until no challenge is pending (default 300 s); rc 3 if still there

Stdlib only; the API is reached directly on the sandbox network (BH_BROWSER_URL, BH_BROWSER_TOKEN).
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

USAGE = __doc__.split("\n\n", 2)[2].split("\n\n")[0]
WAIT_HUMAN_S = 300  # under the Bash tool's default timeout (BASH_DEFAULT_TIMEOUT_MS=330000 in the runner)
POLL_S = 10
STATE_TIMEOUT_S = 15  # one poll; the last one ends before WAIT_HUMAN_S + STATE_TIMEOUT_S < 330 s
UPLOAD_MAX = 256 * 1024
RESUME = (
    "challenge cleared: check `bh-web text --tail 2000` that your pending message went out "
    "(press Enter once if not), then resume your current intent"
)
SWITCH_COST = (
    "switch asked: the host wipes the profile and loads that identity within ~10 s (live identities of this program "
    "only). Cost: a new app session, so one more human challenge for the operator. Poll `bh-web state` until "
    "identity is the one asked; switch_error says why it was refused"
)


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


def _flags(rest: list[str], spec: dict[str, str]) -> dict | None:
    """--name value / --flag options -> request fields; spec: option -> "int" | "str" | "bool". None on a bad line."""
    out: dict = {}
    i = 0
    while i < len(rest):
        opt = rest[i]
        kind = spec.get(opt)
        if kind is None:
            return None
        field = opt[2:]
        if kind == "bool":
            out[field] = True
            i += 1
            continue
        if i + 1 >= len(rest):
            return None
        v = rest[i + 1]
        if kind == "int":
            if not v.isdigit():
                return None
            out[field] = int(v)
        else:
            out[field] = v
        i += 2
    return out


def _upload(css: str, path: str) -> dict | None:
    try:
        with open(path, "rb") as fh:
            data = fh.read(UPLOAD_MAX + 1)
    except OSError:
        return None
    if len(data) > UPLOAD_MAX:
        return None
    name = os.path.basename(path) or "upload.bin"
    return {"op": "upload", "css": css, "name": name, "content_b64": base64.b64encode(data).decode()}


def request_for(argv: list[str]) -> dict | None:
    """The API request for a command line, None when it does not parse (pure, except upload reading its file)."""
    if not argv:
        return None
    op, rest = argv[0], argv[1:]
    if op == "state" and not rest:
        return {"op": op}
    if op in ("goto", "click", "press", "switch") and len(rest) == 1:
        key = {"goto": "url", "click": "css", "press": "key", "switch": "identity"}[op]
        return {"op": op, key: rest[0]}
    if op == "fill" and len(rest) == 2:
        return {"op": "fill", "css": rest[0], "text": rest[1]}
    if op == "wait" and len(rest) == 1:
        return {"op": "wait", "ms": int(rest[0])} if rest[0].isdigit() else {"op": "wait", "css": rest[0]}
    if op == "attr" and len(rest) == 2:
        return {"op": "attr", "css": rest[0], "name": rest[1]}
    if op == "upload" and len(rest) == 2:
        return _upload(rest[0], rest[1])
    opts = {
        "text": {"--css": "str", "--tail": "int"},
        "outline": {"--css": "str"},
        "net": {"--last": "int", "--denied": "bool"},
        "frames": {"--last": "int"},
        "tabs": {"--select": "int"},
    }
    if op in opts:
        f = _flags(rest, opts[op])
        return None if f is None else {"op": op, **f}
    return None


def _print(out: dict, op: str = "") -> int:
    if "text" in out and "error" not in out and op in ("text", ""):
        print(out["text"])
        if out.get("truncated"):
            where = "start" if out.get("from") == "tail" else "end"
            print(f"[truncated at the {where}: {out.get('length')} characters in all]")
        return 0
    if "outline" in out and "error" not in out:
        print(out["outline"])
        if out.get("truncated"):
            print("[truncated]")
        return 0
    if op == "frames" and "frames" in out:
        for f in out["frames"]:
            print(json.dumps(f, ensure_ascii=False))
        return 0
    if op == "net" and "requests" in out:
        for r in out["requests"]:
            print(json.dumps(r, ensure_ascii=False))
        return 0
    print(json.dumps(out, ensure_ascii=False))
    if out.get("error") == "human-needed":
        print("a human challenge is on screen: run `bh-web wait-human`; never try to pass it yourself", file=sys.stderr)
        return 3
    if out.get("error") == "human-viewing":
        print("the operator is at the screen: only state, text and frames until he closes it", file=sys.stderr)
        return 3
    if out.get("error") == "fill-budget":
        print("prompt budget spent: no more fill; work another surface", file=sys.stderr)
        return 4
    if op == "switch" and out.get("switch_requested"):
        print(SWITCH_COST, file=sys.stderr)
    return 1 if out.get("error") else 0


def wait_human(timeout: float, call=_call, sleep=time.sleep, clock=time.monotonic) -> int:
    end = clock() + timeout
    while True:
        st = call({"op": "state"}, STATE_TIMEOUT_S)
        ch = st.get("challenge") or {}
        if st.get("error"):
            print(json.dumps(st))
            return 1
        if not ch.get("pending"):
            print(
                json.dumps(
                    {
                        "challenge": "cleared",
                        "url": st.get("url"),
                        "cleared_at": ch.get("cleared_at"),
                        "human_done_at": st.get("human_done_at"),
                    }
                )
            )
            print(RESUME, file=sys.stderr)
            return 0
        if clock() >= end:
            print(json.dumps({"challenge": "still pending", "since": ch.get("since")}))
            print(
                "not solved yet: `bh-note blocked captcha ...`, work on another surface, check `bh-web state` later",
                file=sys.stderr,
            )
            return 3
        sleep(min(POLL_S, max(0.0, end - clock())))


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
        if argv[:1] == ["upload"]:
            sys.exit(f"bh-web upload: the file must be readable and at most {UPLOAD_MAX} bytes")
        sys.exit(USAGE)
    sys.exit(_print(_call(req), req["op"]))
