"""Canary secrets (I1): `BH-SECRET-<16 hex>` planted in one test account's data and looked for everywhere the gate sees.

Pure (no mitmproxy): the addon calls `find` on a request's URL and body, a response's body and every websocket frame,
on the whole content before any truncation, and journals each hit (event `canary`, see bh.gate.addon). Nothing but
the token itself ever leaves this module: the journal never holds the content around it.

Digest (T24): every token found is a `Hit`, a str (the token, so every caller comparing strings is unchanged) that
also carries `sha256`, the hex SHA-256 of the normalized token's ASCII bytes (`digest`). The gate journals it as the
event's `sha256`: a canary the host planted (bh.accounts.canary) is known to the host by that digest only, and the
observation proof compares digests (bh.runner.observation, `token_sha256`).

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

import hashlib
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


def normalize(token: str) -> str:
    """`BH-SECRET-<lowercase hex>`: the form the gate journals and digests (a host name carries it lowercased)."""
    return "BH-SECRET-" + token[10:].lower()


def digest(token: str) -> str:
    """Hex SHA-256 of the normalized token (ASCII): what the host keeps of a canary it planted."""
    return hashlib.sha256(normalize(token).encode("ascii")).hexdigest()


class Hit(str):
    """A token found: the normalized token itself, with its `sha256` (digest)."""

    sha256: str

    def __new__(cls, token: str) -> Hit:
        hit = super().__new__(cls, token)
        hit.sha256 = digest(token)
        return hit


def find(data: bytes | str | None, limit: int = SCAN_BYTES) -> list[Hit]:
    """Distinct canary tokens in the first `limit` bytes of `data`, in order of appearance, normalized to
    `BH-SECRET-<lowercase hex>` (a host name carries it lowercased), each with its digest (`Hit.sha256`)."""
    if not data:
        return []
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogateescape")
    out: list[Hit] = []
    for m in TOKEN.finditer(data, 0, limit):
        tok = normalize(m.group(0).decode("ascii"))
        if tok not in out:
            out.append(Hit(tok))
            if len(out) >= MAX_HITS:
                break
    return out
