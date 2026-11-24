"""`q` and `qq`: short hand-made requests, so a test costs a few tokens instead of a long curl line.

Measured on the lab runs (124 tool calls): the target origin was typed 129 times, the identity header
about 60 times, `| head -c N` and `-w '%{http_code}'` on most manual requests. Each of these lines cost
~40 tokens to write and stays in the context for the rest of the segment.

  q  [-a ID] [-X METHOD] [-d BODY | -j JSON] [-H 'K: V']... [-n BYTES] [-i] [-t S] URL|/path
     One request through the gate (curl, proxy from the environment). Prints `[status] size type`, then
     the first BYTES of the body (default 400). The full body goes to raw/ and its path is printed.
  qq [-H 'K: V']... [-n BYTES] URL|/path
     The same GET as every identity of the program and without a session: one line each with status,
     size and a short hash, so an access-control difference shows at a glance. GET only.
  q -b URL   sets the origin that `/path` arguments use (any absolute URL given to q also sets it).

The tool lock and the "tested" record see these like curl (contract.urls_in resolves `/path`).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from bh.agent import contract as c

BASE_FILE = "q-base"


def base_path() -> Path:
    return c.bh_dir() / BASE_FILE


def read_base() -> str | None:
    try:
        b = base_path().read_text().strip()
    except OSError:
        return None
    return b or None


def resolve(target: str, base: str | None) -> str:
    if "://" in target:
        return target
    if not target.startswith("/"):
        raise SystemExit(f"q: {target!r} is neither an absolute URL nor a /path")
    if not base:
        raise SystemExit("q: no origin yet for a /path: give an absolute URL once, or `q -b https://host`")
    return base.rstrip("/") + target


def remember(url: str) -> None:
    o = c.origin(url)
    if o and not c.is_passive(c.host_of(url)):
        base_path().parent.mkdir(parents=True, exist_ok=True)
        base_path().write_text(o + "\n")


def identities() -> list[str]:
    return [i for i in os.environ.get("BH_IDENTITIES", "").split(",") if i]


def fetch(url: str, *, method: str, headers: list[str], body: str | None, timeout: float, show_headers: bool):
    """One curl through the gate. Returns (status, size, content type, body bytes, header text)."""
    with tempfile.TemporaryDirectory() as tmp:
        out, hdr = Path(tmp) / "body", Path(tmp) / "headers"
        cmd = [
            "curl",
            "-sS",
            "-m",
            f"{timeout:g}",
            "-o",
            str(out),
            "-w",
            "%{http_code} %{size_download} %{content_type}",
        ]
        cmd += ["-X", method] if method != "GET" else []
        cmd += ["-D", str(hdr)] if show_headers else []
        for h in headers:
            cmd += ["-H", h]
        if body is not None:
            cmd += ["--data-binary", body]
        cmd.append(url)
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        status, size, ctype = ([*p.stdout.split(" ", 2), "", "", ""])[:3]
        data = out.read_bytes() if out.exists() else b""
        head = hdr.read_text(errors="replace") if show_headers and hdr.exists() else ""
        if p.returncode and not p.stdout.strip("0 "):
            if "CONNECT tunnel failed, response 403" in p.stderr:
                raise SystemExit(f"[gate] DENIED {c.origin(url)}: out of scope or forbidden. Do not retry it.")
            raise SystemExit(f"q: curl failed ({p.returncode}): {p.stderr.strip()[:200]}")
        return status, size, ctype.strip(), data, head


def keep_raw(data: bytes, label: str) -> Path:
    raw = c.bh_dir() / c.RAW
    raw.mkdir(parents=True, exist_ok=True)
    path = raw / f"{int(time.time())}-q-{hashlib.sha1(data).hexdigest()[:8]}-{label}.body"
    path.write_bytes(data)
    return path


def _common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("target", nargs="?")
    ap.add_argument("-H", dest="headers", action="append", default=[], metavar="'K: V'")
    ap.add_argument("-n", type=int, default=400, metavar="BYTES", help="body bytes shown (0: none)")
    ap.add_argument("-t", type=float, default=20, metavar="S", help="timeout")


def main_q(args: list[str]) -> None:
    ap = argparse.ArgumentParser(prog="q", description="one request through the gate, compact output")
    _common(ap)
    ap.add_argument("-a", dest="who", metavar="ID", help="identity (session injected by the gate)")
    ap.add_argument("-X", dest="method", default=None)
    ap.add_argument("-d", dest="data")
    ap.add_argument("-j", dest="json", help="JSON body (sets Content-Type)")
    ap.add_argument("-i", action="store_true", help="show the response headers")
    ap.add_argument("-b", dest="base", help="set the origin used by /path")
    a = ap.parse_args(args)
    if a.base:
        remember(resolve(a.base, None))
        if not a.target:
            print(f"q: base {read_base()}")
            return
    if not a.target:
        ap.error("URL or /path required")
    url = resolve(a.target, read_base())
    headers = list(a.headers)
    if a.who:
        headers.append(f"{c.IDENTITY_HEADER}: {a.who}")
    body = a.json if a.json is not None else a.data
    if a.json is not None:
        headers.append("Content-Type: application/json")
    method = (a.method or ("POST" if body is not None else "GET")).upper()
    status, size, ctype, data, head = fetch(
        url, method=method, headers=headers, body=body, timeout=a.t, show_headers=a.i
    )
    if not data.startswith(b"bh-gate: DENIED"):
        remember(url)
    print(f"[{status}] {size}B {ctype}".rstrip())
    if head:
        print("\n".join(head.splitlines()[1:16]))
    if a.n and data:
        print(data[: a.n].decode("utf-8", "replace"))
    if len(data) > a.n:
        print(f"[q] +{len(data) - a.n}B, full body: {keep_raw(data, status)}")


def main_qq(args: list[str]) -> None:
    ap = argparse.ArgumentParser(prog="qq", description="same GET as every identity and anonymous")
    _common(ap)
    ap.set_defaults(n=80)
    a = ap.parse_args(args)
    if not a.target:
        ap.error("URL or /path required")
    url = resolve(a.target, read_base())
    whos = [*identities(), None]
    if len(whos) == 1:
        print("[qq] no identity for this program: only the anonymous request is sent")
    seen: dict[str, str] = {}
    for who in whos:
        headers = list(a.headers) + ([f"{c.IDENTITY_HEADER}: {who}"] if who else [])
        status, size, _, data, _ = fetch(url, method="GET", headers=headers, body=None, timeout=a.t, show_headers=False)
        digest = hashlib.sha1(data).hexdigest()[:8]
        same = f" =={seen[digest]}" if digest in seen else ""
        seen.setdefault(digest, who or "anon")
        snippet = " ".join(data[: a.n].decode("utf-8", "replace").split()) if a.n else ""
        if who is None and status != "000":
            remember(url)
        print(f"{who or 'anon':<10} [{status}] {size:>7}B {digest}{same}  {snippet}")
        if data:
            keep_raw(data, f"{who or 'anon'}-{status}")


def main(name: str, args: list[str]) -> None:
    if name == "qq" and any(x in ("-X", "-d", "-j") for x in args):
        sys.exit("qq: GET only; send a write once, as one of your identities: q -a <identity> -X ...")
    (main_qq if name == "qq" else main_q)(args)
