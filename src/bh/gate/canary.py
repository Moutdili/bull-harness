"""Canary secrets (I1): `BH-SECRET-<16 hex>` planted in one test account's data and looked for everywhere the gate sees.

Pure (no mitmproxy): the addon calls `find` on a request's URL and body, a response's body and every websocket frame,
on the whole content before any truncation, and journals each hit (event `canary`, see bh.gate.addon). Nothing but
the token itself ever leaves this module: the journal never holds the content around it.

Bounds: at most SCAN_BYTES of each content are looked at (after decoding), at most MAX_HITS distinct tokens are
reported per content. A compressed body (Content-Encoding gzip, deflate, br, zstd) is decoded with an output limit of
SCAN_BYTES, so a decompression bomb costs SCAN_BYTES of memory, never more:
- gzip / deflate: zlib's `decompressobj().decompress(data, max_length)` (stdlib);
- br: `brotli.Decompressor().process(data, output_buffer_limit=...)` (Brotli >= 1.2.0; the gate image ships 1.2.1,
  imported by mitmproxy/net/encoding.py);
- zstd: `compression.zstd.ZstdDecompressor().decompress(data, max_length)` (stdlib, Python >= 3.14; the gate image
  runs 3.15).
A codec that is missing or fails leaves the raw bytes, which are still scanned (fail open on the scan, never on the
flow: the scan decides nothing).
"""

from __future__ import annotations

import re
import zlib

TOKEN = re.compile(rb"bh-secret-[0-9a-f]{16}(?![0-9a-f])", re.I)
SCAN_BYTES = 2 << 20  # per content
MAX_HITS = 16  # distinct tokens reported per content
WHERE = ("request-url", "request-body", "response-body", "ws-client", "ws-server")
CLIENTS = ("browser", "agent", "judge", "login", "other")


def _zlib(data: bytes, wbits: int, limit: int) -> bytes:
    return zlib.decompressobj(wbits).decompress(data, limit)


def _brotli(data: bytes, limit: int) -> bytes:
    import brotli  # the gate image's (mitmproxy's dependency); absent elsewhere

    return brotli.Decompressor().process(data, output_buffer_limit=limit)[:limit]


def _zstd(data: bytes, limit: int) -> bytes:
    from compression import zstd  # Python >= 3.14

    return zstd.ZstdDecompressor().decompress(data, limit)


def decode(data: bytes, encoding: str | None, limit: int = SCAN_BYTES) -> bytes:
    """`data` decoded along its Content-Encoding (last applied first), each step bounded to `limit` bytes of output.
    Unknown or failing codec: the bytes as they are."""
    for enc in reversed([e.strip().lower() for e in (encoding or "").split(",") if e.strip()]):
        try:
            if enc in ("gzip", "x-gzip"):
                data = _zlib(data, 16 + zlib.MAX_WBITS, limit)
            elif enc == "deflate":
                try:
                    data = _zlib(data, zlib.MAX_WBITS, limit)
                except zlib.error:
                    data = _zlib(data, -zlib.MAX_WBITS, limit)  # raw deflate, as some servers send it
            elif enc == "br":
                data = _brotli(data, limit)
            elif enc == "zstd":
                data = _zstd(data, limit)
            elif enc != "identity":
                return data
        except Exception:  # noqa: BLE001 - a broken or missing codec: scan what we have
            return data
    return data


def find(data: bytes | str | None, limit: int = SCAN_BYTES) -> list[str]:
    """Distinct canary tokens in the first `limit` bytes of `data`, in order of appearance, normalized to
    `BH-SECRET-<lowercase hex>` (a host name carries it lowercased)."""
    if not data:
        return []
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogateescape")
    out: list[str] = []
    for m in TOKEN.finditer(data, 0, limit):
        tok = "BH-SECRET-" + m.group(0)[10:].decode("ascii").lower()
        if tok not in out:
            out.append(tok)
            if len(out) >= MAX_HITS:
                break
    return out
