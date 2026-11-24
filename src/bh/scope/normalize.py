"""Target parsing and normalization.

Every network-facing component (gate, DNS, SOCKS, builtins) must go through
these functions so that one parser decides what a target *is*. Any input that
two parsers could read differently (backslashes, whitespace, control chars in
the authority) is rejected instead of guessed.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
import socket
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# Legacy IPv4 spellings accepted by inet_aton / curl: 2130706433, 0x7f.1, 0177.0.0.1
_LEGACY_V4 = re.compile(r"(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+)){0,3}", re.I)
# Characters allowed in an authority once userinfo is gone (host, brackets, port).
_AUTHORITY_OK = re.compile(r"[A-Za-z0-9._~%!$&'()*+,;=:\[\]@-]*")


class TargetError(ValueError):
    """The target cannot be parsed unambiguously."""


@dataclass(frozen=True)
class Target:
    raw: str
    host: str | None  # normalized hostname (punycode, lower, no trailing dot); None if IP
    ip: IPAddress | None
    scheme: str | None  # None for bare host / host:port
    port: int | None  # explicit or scheme default; None if unknown
    path: str | None  # normalized path, None for bare host
    path_raw: str | None  # percent-decoded, not dot-normalized
    # every reading of the path a server might apply (see path_variants); () for bare hosts
    paths: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.host if self.host is not None else str(self.ip)


def norm_host(host: str) -> str:
    h = host.strip()
    if h.endswith("."):
        h = h[:-1]
    h = h.lower()
    if not h or any(c.isspace() for c in h):
        raise TargetError(f"invalid host {host!r}")
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetError(f"invalid host {host!r}: {exc}") from exc
    if h.startswith("-") or ".." in h:
        raise TargetError(f"invalid host {host!r}")
    return h


def parse_ip(host: str) -> IPAddress | None:
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if _LEGACY_V4.fullmatch(h):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(h))
        except OSError:
            return None
    return None


def norm_path(path: str | None) -> tuple[str, str]:
    """Return (normalized, raw_decoded). Query/fragment must already be stripped."""
    decoded = unquote(path or "/").replace("\\", "/")
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    raw = re.sub(r"/+", "/", decoded)
    normalized = posixpath.normpath(raw)
    normalized = re.sub(r"/+", "/", normalized)
    if raw.endswith("/") and normalized != "/":
        normalized += "/"
    return normalized, raw


def _check_authority(netloc: str, raw: str) -> None:
    if not netloc:
        raise TargetError(f"no host in {raw!r}")
    if "\\" in netloc or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in netloc):
        raise TargetError(f"ambiguous authority in {raw!r}")
    if netloc.count("@") > 1:
        raise TargetError(f"ambiguous authority in {raw!r}")
    host_part = netloc.rpartition("@")[2]
    if host_part.isascii() and not _AUTHORITY_OK.fullmatch(host_part):
        raise TargetError(f"ambiguous authority in {raw!r}")
    # non-ASCII host parts are validated by IDNA in norm_host


def _split_hostport(s: str) -> tuple[str, int | None]:
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            raise TargetError(f"bad IPv6 literal {s!r}")
        host, rest = s[: end + 1], s[end + 1 :]
        if not rest:
            return host, None
        if not rest.startswith(":"):
            raise TargetError(f"bad host:port {s!r}")
        return host, _port(rest[1:], s)
    if s.count(":") > 1:  # bare IPv6 without port
        return s, None
    host, sep, port = s.partition(":")
    return host, (_port(port, s) if sep else None)


def _port(p: str, raw: str) -> int:
    if not p.isdigit() or not 0 < int(p) < 65536:
        raise TargetError(f"bad port in {raw!r}")
    return int(p)


_MATRIX = re.compile(r";[^/]*")


def path_variants(path: str) -> tuple[str, ...]:
    """The path as different servers may read it: raw, decoded once and twice (%252f), with
    matrix parameters dropped (`/a;x/b`, `/..;/`), dot-normalized or not. Out-of-scope rules
    must match ANY reading, in-scope rules must hold for ALL of them."""
    once = unquote(path)
    out: set[str] = set()
    for p in {path, once, unquote(once)}:
        for q in {p, _MATRIX.sub("", p)}:
            out.update(norm_path(q))
    return tuple(sorted(out))


def _make(raw: str, host_s: str, scheme: str | None, port: int | None, path: str | None) -> Target:
    ip = parse_ip(host_s)
    host = None if ip is not None else norm_host(host_s)
    if port is None and scheme is not None:
        port = DEFAULT_PORTS.get(scheme)
    if path is None:
        return Target(raw, host, ip, scheme, port, None, None)
    normalized, decoded = norm_path(path)
    return Target(raw, host, ip, scheme, port, normalized, decoded, path_variants(path))


def parse_target(raw: str) -> Target:
    """Parse a URL, host, IP, or host:port into a Target. Anything unparseable raises TargetError (the stdlib's
    ValueError / UnicodeError from urlsplit, idna or ipaddress included): callers refuse, they never crash."""
    try:
        return _parse_target(raw)
    except TargetError:
        raise
    except (ValueError, UnicodeError, TypeError, AttributeError) as exc:
        raise TargetError(f"unparseable target {str(raw)[:120]!r}: {exc}") from exc


def _parse_target(raw: str) -> Target:
    s = raw.strip()
    if not s:
        raise TargetError("empty target")
    if "://" in s:
        scheme = s.split("://", 1)[0].lower()
        if scheme not in DEFAULT_PORTS:
            raise TargetError(f"unsupported scheme {scheme!r}")
        parts = urlsplit(s)
        _check_authority(parts.netloc, raw)
        try:
            port = parts.port
        except ValueError as exc:
            raise TargetError(f"bad port in {raw!r}") from exc
        host = parts.hostname
        if not host:
            raise TargetError(f"no host in {raw!r}")
        if ":" in host:  # urlsplit strips brackets from IPv6
            host = f"[{host}]"
        return _make(raw, host, scheme, port, parts.path or "/")
    if "/" in s or "\\" in s or "@" in s or any(c.isspace() for c in s):
        raise TargetError(f"ambiguous target {raw!r}: use a full URL")
    host, port = _split_hostport(s)
    return _make(raw, host, None, port, None)
