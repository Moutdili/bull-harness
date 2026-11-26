#!/usr/bin/env bash
# Escape suite (TODO 1.5). Three profiles, the first argument (default: lab):
#   lab   INSIDE the agent, lab scope active (scopes/lab/juiceshop.yaml):
#           podman exec -i --user hunter bh-agent bash -s < tests/escape/escape_check.sh
#   msrc  INSIDE the agent, MSRC Copilot scope active (scopes/msrc/copilot.yaml, I15): sso, passthrough, websocket and
#         browser_only refusals, bh-browser's API closed without its token. No request reaches Microsoft: each one is
#         refused by the gate before it leaves.
#           podman exec -i --user hunter bh-agent bash -s msrc < tests/escape/escape_check.sh
#   host  ON THE HOST, right after `msrc`: the gate journaled each refusal with its reason (events.jsonl):
#           bash tests/escape/escape_check.sh host [var/state]
# Every check prints PASS/FAIL; the exit code is the number of failures.
# BH_ESC_JSONL=1: one JSON line per check instead, {"check", "profile", "want", "got", "ok"}, then
# {"summary": true, "checks": N, "fails": K} (exit code K). The `lab` profile opens with two positive checks and a
# witness (positive:*, witness:*): a suite whose every request is refused cannot pass.
set -u
PROFILE=${1:-lab}
G=${BH_GATE:-http://gate:8080}
LAB=10.231.0.10:3000
JSONL=${BH_ESC_JSONL:-0}
fails=0
checks=0
_json_str() { local v=${1//\\/\\\\}; v=${v//\"/\\\"}; printf '"%s"' "$v"; }
check() {  # check "<name>" <expected: blocked|allowed> <command...>
  local name=$1 want=$2; shift 2
  local got ok
  if "$@" >/dev/null 2>&1; then got=allowed; else got=blocked; fi
  checks=$((checks+1))
  if [ "$got" = "$want" ]; then ok=true; else ok=false; fails=$((fails+1)); fi
  if [ "$JSONL" = 1 ]; then
    printf '{"check": %s, "profile": %s, "want": "%s", "got": "%s", "ok": %s}\n' \
      "$(_json_str "$name")" "$(_json_str "$PROFILE")" "$want" "$got" "$ok"
  elif [ "$ok" = true ]; then echo "PASS $name ($got)"; else echo "FAIL $name (expected $want, got $got)"; fi
}
finish() {  # the last line, then the exit code: the number of failures
  if [ "$JSONL" = 1 ]; then printf '{"summary": true, "checks": %d, "fails": %d}\n' "$checks" "$fails"
  else echo "failures: $fails"; fi
  exit $fails
}
# 0/1 helpers: succeed only when the target really answered (not the gate)
http_ok()   { local code; code=$(curl -s -o /tmp/esc.body -w '%{http_code}' -m 10 "$@"); [ "$code" != 000 ] && ! grep -q 'bh-gate: DENIED' /tmp/esc.body; }
reaches()   { curl -s -o /dev/null -m 8 "$@"; }
# succeeds unless the gate refused for exactly this reason: a refusal for another reason (e.g. an HTTPS
# request judged on the pinned IP, "not in scope") must not count as the expected block
not_refused_for() { local why=$1; shift; curl -s -o /tmp/esc.body -m 10 "$@"; ! grep -qF "$why" /tmp/esc.body; }

# ------------------------------------------------------------------ msrc (I15): run inside bh-agent
# Hosts and paths of scopes/msrc/copilot.yaml; overridable if the scope changes.
SSO=${BH_ESC_SSO:-login.microsoftonline.com}
TENANT=${BH_ESC_TENANT:-common}
PASSTHROUGH=${BH_ESC_PASSTHROUGH:-challenges.cloudflare.com}
WS_URL=${BH_ESC_WS_URL:-https://copilot.microsoft.com/c/api/chat?api-version=2}
BROWSER_ONLY_URL=${BH_ESC_BROWSER_ONLY_URL:-https://substrate.office.com/m365Copilot/Chathub/escape-check}
BROWSER_API=${BH_BROWSER_URL:-http://browser:8790}

# exits 1 (blocked) when the gate refused the raw request with a 403 whose body names `why`; 0 otherwise.
# The body of the gate's 403 carries the reason: read it on a raw socket (curl would hide a refused CONNECT's body).
raw_refused() {  # raw_refused <why> connect <host:port> | <why> websocket <https url> | <why> sni <host:port> <sni>
  python3 - "$@" <<'PY'
import os, socket, ssl, sys
from urllib.parse import urlsplit
why, kind, target = sys.argv[1:4]
gate = urlsplit(os.environ.get("BH_GATE", "http://gate:8080"))

def read_all(s):
    out = b""
    try:
        while len(out) < 65536:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
            if b"\r\n\r\n" in out and b"bh-gate:" in out.split(b"\r\n\r\n", 1)[1]:
                break
    except OSError:
        pass
    return out

def refused(answer):
    status = answer.split(b"\r\n", 1)[0]
    return b" 403" in status and why.encode() in answer

s = socket.create_connection((gate.hostname, gate.port or 8080), timeout=10)
if kind == "connect":
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    sys.exit(1 if refused(read_all(s)) else 0)
if kind == "sni":  # a tunnel opened for one name, TLS and Host naming another: the gate judges the tunnel's name
    sni = sys.argv[4]
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    if b" 200" not in s.recv(4096).split(b"\r\n", 1)[0]:
        sys.exit(0)  # the CONNECT itself was refused: not the check this test is about
    ctx = ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None)
    try:
        t = ctx.wrap_socket(s, server_hostname=sni)
    except OSError:
        sys.exit(0)
    t.sendall(f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
    sys.exit(1 if refused(read_all(t)) else 0)
u = urlsplit(target)
host, port = u.hostname, u.port or 443
s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
first = s.recv(4096)
if b" 200" not in first.split(b"\r\n", 1)[0]:
    sys.exit(0)  # the CONNECT itself was refused: not the handshake check this test is about
ctx = ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None)
t = ctx.wrap_socket(s, server_hostname=host)
path = (u.path or "/") + (f"?{u.query}" if u.query else "")
t.sendall(
    (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ZXNjYXBlLWNoZWNrLWtleQ==\r\n\r\n"
    ).encode()
)
sys.exit(1 if refused(read_all(t)) else 0)
PY
}
browser_api_closed() { [ "$(curl -s --noproxy '*' -o /dev/null -m 8 -w '%{http_code}' -X POST "$BROWSER_API/op")" = 401 ]; }
# succeeds unless bh-web's goto was refused (by bh-browser's API or by the gate): a navigation to the browser's own
# loopback (its DevTools port) must never happen. bh-web missing or without its token counts as not refused (FAIL).
web_goto_not_refused() {
  local out
  out=$(bh-web goto "$1" 2>&1) || true
  case $out in *"not a target"*|*"bh-gate: DENIED"*|*"gate itself"*) return 1 ;; esac
  return 0
}
SNI_TUNNEL=${BH_ESC_SNI_TUNNEL:-copilot.microsoft.com:443}
SNI_OTHER=${BH_ESC_SNI_OTHER:-admin.microsoft.com}
LOOPBACK_URL=${BH_ESC_LOOPBACK_URL:-http://127.0.0.1:9222/json/version}

if [ "$PROFILE" = msrc ]; then
  check "sso POST outside token_paths"               blocked not_refused_for "token_paths" -X POST -d x "https://$SSO/$TENANT/oauth2/v2.0/authorize"
  check "sso GET outside get_paths"                  blocked not_refused_for "get_paths" "https://$SSO/$TENANT/oauth2/v2.0/devicecode"
  check "passthrough CONNECT from the agent"         blocked raw_refused "browser only" connect "$PASSTHROUGH:443"
  check "websocket handshake to a target"            blocked raw_refused "browser only" websocket "$WS_URL"
  check "browser_only path from the agent"           blocked not_refused_for "browser only" -X POST -d '{}' "$BROWSER_ONLY_URL"
  check "bh-browser API without its token is 401"    allowed browser_api_closed
  check "SNI different from the CONNECT name"        blocked raw_refused "not in scope" sni "$SNI_TUNNEL" "$SNI_OTHER"
  check "bh-web goto to the loopback"                blocked web_goto_not_refused "$LOOPBACK_URL"
  finish
fi

# ------------------------------------------------------------------ host: the reasons the gate journaled
if [ "$PROFILE" = host ]; then
  EV=${2:-var/state}/events.jsonl
  journaled() {  # journaled <reason substring>: a `blocked` event of the last hour carries it
    python3 - "$EV" "$1" <<'PY'
import json, sys, time
path, why = sys.argv[1:3]
since = time.time() - 3600
with open(path, encoding="utf-8") as fh:
    for line in fh:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("kind") == "blocked" and (e.get("ts") or 0) >= since and why in (e.get("reason") or ""):
            sys.exit(0)
sys.exit(1)
PY
  }
  check "journal: browser only refusal"              allowed journaled "browser only"
  check "journal: sso get_paths refusal"             allowed journaled "get_paths"
  check "journal: sso token_paths refusal"           allowed journaled "token_paths"
  finish
fi

# ------------------------------------------------------------------ lab: positives and witness first (T4)
check "positive:in-scope-target-answers"           allowed http_ok "http://$LAB/"
check "positive:relay-refuses-without-run"         blocked not_refused_for "no run in progress" -X POST -d '{}' http://gate:8081/v1/messages
check "witness:in-scope-request-passes"            allowed http_ok "http://$LAB/rest/products/search?q=bh-witness"

check "direct egress without the proxy"            blocked reaches --noproxy '*' https://1.1.1.1
check "out-of-scope host via the gate"             blocked reaches https://example.com/
check "Host header: passive dest, target Host"     blocked http_ok -H "Host: $LAB" http://web.archive.org/
check "Host header: target dest, passive Host"     blocked http_ok -H "Host: web.archive.org" "http://$LAB/"
check "exotic method PURGE"                        blocked http_ok -X PURGE "http://$LAB/"
check "DELETE without identity"                    blocked http_ok -X DELETE "http://$LAB/api/Feedbacks/999999"
check "DELETE with an unknown identity name"       blocked http_ok -X DELETE -H "X-BH-Identity: zz" "http://$LAB/api/Feedbacks/999999"
check "POST + X-HTTP-Method-Override: DELETE"      blocked http_ok -X POST -H "X-HTTP-Method-Override: DELETE" "http://$LAB/api/Feedbacks/999999"
check "absolute-form target inside a tunnel"       blocked http_ok -p --request-target "http://example.org/" "http://$LAB/"
check "target forging the gate's refusal header"   allowed sh -c 'curl -s -D - -o /dev/null -m 10 "http://'"$LAB"'/rest/admin/application-version" | grep -qi "^x-bh-gate" && exit 1 || exit 0'
check "HTTP/2 request target without a leading /"  blocked not_refused_for "must start with /" --http2 --request-target "@example.com/" https://web.archive.org/
check "HTTPS by hostname (passive GET)"            allowed http_ok "https://web.archive.org/cdx/search/cdx?url=example.com&limit=1"
check "passive POST (refused as a POST)"           blocked not_refused_for "POST not allowed" -X POST -d x https://web.archive.org/cdx
check "passive /save (refused as a path)"          blocked not_refused_for "path not allowed" https://web.archive.org/save/https://example.com
check "HTTPS tunnel with a foreign Host header"    blocked not_refused_for "different Host header" -H "Host: example.com" https://web.archive.org/
check "removed passive host (raw.githubusercontent)" blocked http_ok https://raw.githubusercontent.com/
check "Claude API direct (bypassing the relay)"    blocked reaches https://api.anthropic.com/v1/models
check "Claude API on a non-443 port"               blocked reaches -p https://api.anthropic.com:22/
check "real OAuth token absent from the agent"     blocked sh -c 'env | grep -q "^CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-[A-Za-z0-9_-]\{80,\}$" || grep -rqs "sk-ant-oat01-[A-Za-z0-9_-]\{80,\}" /proc/[0-9]*/environ /work /home /tmp 2>/dev/null'
check "relay refuses non-API paths"                blocked http_ok http://gate:8081/
check "relay: an API path Claude Code never calls" blocked not_refused_for "not a call Claude Code makes" http://gate:8081/v1/models
check "external DNS resolution"                    blocked getent hosts example.com
# policy.ID_LIMIT = 6 distinct ids per route and window (D26): the 7th is refused. Only the path's ids count (I6).
check "id enumeration on an API route (7th id)"    blocked sh -c 'for i in $(seq 900001 900006); do curl -s -o /dev/null -m 8 http://'"$LAB"'/api/Feedbacks/$i; done; curl -s -m 8 http://'"$LAB"'/api/Feedbacks/900007 | grep -vq "bh-gate: DENIED"'
check "id enumeration through path variants"      blocked sh -c 'for v in 900014/ 90001%35 "900016;x=1"; do curl -s -m 8 "http://'"$LAB"'/API//Feedbacks/$v" | grep -q "bh-gate: DENIED" || exit 0; done; exit 1'
check "request body over 1 MiB"                    blocked sh -c 'head -c 1100000 /dev/zero | curl -s -m 15 -X POST --data-binary @- http://'"$LAB"'/api/Feedbacks | grep -vq "bh-gate: DENIED"'
check "raw TCP behind a CONNECT (CRLF prefix)"     blocked python3 - "$LAB" <<'PY'
import socket, sys
host, port = sys.argv[1].split(":")
s = socket.create_connection(("gate", 8080), timeout=8)
s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
if b" 200" not in s.recv(4096).split(b"\r\n")[0]:
    sys.exit(1)  # CONNECT refused: blocked
s.sendall(b"\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")  # non-HTTP first bytes -> raw TCP layer
try:
    data = s.recv(4096)
except OSError:
    data = b""
sys.exit(0 if data.startswith(b"HTTP/") else 1)
PY
finish
