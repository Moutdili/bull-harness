#!/usr/bin/env bash
# Escape suite (TODO 1.5): run INSIDE the agent, with the lab scope active (scopes/lab/juiceshop.yaml):
#   podman exec -i --user hunter bh-agent bash -s < tests/escape/escape_check.sh
# Every check prints PASS/FAIL; the exit code is the number of failures.
set -u
G=${BH_GATE:-http://gate:8080}
LAB=10.231.0.10:3000
fails=0
check() {  # check "<name>" <expected: blocked|allowed> <command...>
  local name=$1 want=$2; shift 2
  local got
  if "$@" >/dev/null 2>&1; then got=allowed; else got=blocked; fi
  if [ "$got" = "$want" ]; then echo "PASS $name ($got)"; else echo "FAIL $name (expected $want, got $got)"; fails=$((fails+1)); fi
}
# 0/1 helpers: succeed only when the target really answered (not the gate)
http_ok()   { local code; code=$(curl -s -o /tmp/esc.body -w '%{http_code}' -m 10 "$@"); [ "$code" != 000 ] && ! grep -q 'bh-gate: DENIED' /tmp/esc.body; }
reaches()   { curl -s -o /dev/null -m 8 "$@"; }

check "direct egress without the proxy"            blocked reaches --noproxy '*' https://1.1.1.1
check "out-of-scope host via the gate"             blocked reaches https://example.com/
check "lab target via the gate"                    allowed http_ok "http://$LAB/"
check "Host header: passive dest, target Host"     blocked http_ok -H "Host: $LAB" http://web.archive.org/
check "Host header: target dest, passive Host"     blocked http_ok -H "Host: web.archive.org" "http://$LAB/"
check "exotic method PURGE"                        blocked http_ok -X PURGE "http://$LAB/"
check "DELETE without identity"                    blocked http_ok -X DELETE "http://$LAB/api/Feedbacks/999999"
check "passive POST"                               blocked http_ok -X POST -d x https://web.archive.org/cdx
check "passive server-side fetch /save"            blocked http_ok https://web.archive.org/save/https://example.com
check "removed passive host (raw.githubusercontent)" blocked http_ok https://raw.githubusercontent.com/
check "Claude API on a non-443 port"               blocked reaches -p https://api.anthropic.com:22/
check "external DNS resolution"                    blocked getent hosts example.com
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
check "Claude API TLS passthrough (real cert)"     allowed sh -c "echo | openssl s_client -proxy gate:8080 -connect api.anthropic.com:443 -servername api.anthropic.com 2>/dev/null | grep -q 'Google Trust Services'"
echo "failures: $fails"
exit $fails
