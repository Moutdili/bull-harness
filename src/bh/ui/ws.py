"""A minimal WebSocket server side (RFC 6455), stdlib only: enough to carry noVNC's RFB stream.

The UI terminates the WebSocket itself and relays the bytes to x11vnc through a `podman exec` pipe
(bh.browser_service.host.open_tunnel): no websockify, no listening port in bh-browser that a web page could reach.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import struct
import threading
from typing import BinaryIO

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BIN, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA
MAX_FRAME = 1 << 20  # what a VNC client sends is small (keys, pointer, short messages)


def accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key.strip() + GUID).encode()).digest()).decode()


def valid_key(key: str | None) -> bool:
    try:
        return key is not None and len(base64.b64decode(key.strip(), validate=True)) == 16
    except ValueError:
        return False


def _read_exact(r: BinaryIO, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = r.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_frame(r: BinaryIO, max_len: int = MAX_FRAME) -> tuple[int, bytes] | None:
    """(opcode, payload) of one client frame, None at end of stream. A client frame must be masked."""
    head = _read_exact(r, 2)
    if head is None:
        return None
    b0, b1 = head
    op, masked, n = b0 & 0x0F, b1 & 0x80, b1 & 0x7F
    if not masked:
        raise ValueError("unmasked client frame")
    if n == 126:
        ext = _read_exact(r, 2)
        if ext is None:
            return None
        n = struct.unpack("!H", ext)[0]
    elif n == 127:
        ext = _read_exact(r, 8)
        if ext is None:
            return None
        n = struct.unpack("!Q", ext)[0]
    if n > max_len:
        raise ValueError("frame too large")
    mask = _read_exact(r, 4)
    data = _read_exact(r, n) if n else b""
    if mask is None or data is None:
        return None
    return op, bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def encode_frame(op: int, payload: bytes) -> bytes:
    """A server frame (never masked), FIN set."""
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", 0x80 | op, n)
    elif n < 1 << 16:
        head = struct.pack("!BBH", 0x80 | op, 126, n)
    else:
        head = struct.pack("!BBQ", 0x80 | op, 127, n)
    return head + payload


def relay(rfile: BinaryIO, wfile: BinaryIO, tunnel_in: BinaryIO, tunnel_out: BinaryIO) -> None:
    """Carry bytes both ways until either side ends: client frames -> tunnel_in, tunnel_out -> binary frames."""
    wlock = threading.Lock()

    def send(op: int, payload: bytes) -> None:
        with wlock:
            wfile.write(encode_frame(op, payload))
            with contextlib.suppress(AttributeError):
                wfile.flush()

    def down() -> None:
        fd = tunnel_out.fileno()
        try:
            while True:
                d = os.read(fd, 65536)
                if not d:
                    break
                send(OP_BIN, d)
        except OSError:
            pass
        with contextlib.suppress(OSError):
            send(OP_CLOSE, struct.pack("!H", 1000))

    t = threading.Thread(target=down, daemon=True)
    t.start()
    try:
        while True:
            fr = read_frame(rfile)
            if fr is None:
                break
            op, payload = fr
            if op in (OP_BIN, OP_TEXT, OP_CONT):
                tunnel_in.write(payload)
                tunnel_in.flush()
            elif op == OP_PING:
                send(OP_PONG, payload[:125])
            elif op == OP_CLOSE:
                with contextlib.suppress(OSError):
                    send(OP_CLOSE, payload[:2])
                break
    except (OSError, ValueError):
        pass
    finally:
        with contextlib.suppress(OSError):
            tunnel_in.close()
    t.join(timeout=5)
