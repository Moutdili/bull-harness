#!/bin/bash
# Acceptance for the agent image: every expected binary answers. rc = number of missing tools.
miss=0
for b in claude node python3 jq curl git proxychains4 dig subfinder httpx-toolkit dnsx katana nuclei naabu \
         ffuf feroxbuster gobuster arjun sqlmap dalfox wafw00f whatweb nikto trufflehog gitleaks nmap sslscan semgrep; do
  if command -v "$b" >/dev/null 2>&1; then printf 'ok   %s\n' "$b"; else printf 'MISS %s\n' "$b"; miss=$((miss+1)); fi
done
# bh-recon archive step: gau at the pinned version, gf patterns readable (issue 32).
if v=$(HOME=$(mktemp -d) gau --version 2>/dev/null) && [ "$v" = "gau version: 2.2.4" ]; then echo "ok   gau (2.2.4)"; else echo "MISS gau 2.2.4 (got: ${v:-none})"; miss=$((miss+1)); fi
for n in sqli xss ssrf redirect idor lfi; do
  if python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d.get("patterns") or d.get("pattern")' "/opt/bh/gf/$n.json" 2>/dev/null; then
    printf 'ok   gf pattern %s\n' "$n"; else printf 'MISS gf pattern %s\n' "$n"; miss=$((miss+1)); fi
done
# bh-browse: playwright importable by the isolated interpreter bh-agent uses, headless shell present and readable.
if python3 -I -c "import playwright.sync_api" 2>/dev/null; then echo "ok   playwright (python3 -I)"; else echo "MISS playwright"; miss=$((miss+1)); fi
shell=$(ls "${PLAYWRIGHT_BROWSERS_PATH:-/opt/ms-playwright}"/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell 2>/dev/null | head -1)
if [ -n "$shell" ] && [ -x "$shell" ]; then echo "ok   chrome-headless-shell"; else echo "MISS chrome-headless-shell"; miss=$((miss+1)); fi
if command -v certutil >/dev/null 2>&1; then echo "ok   certutil"; else echo "MISS certutil"; miss=$((miss+1)); fi
# bh-zap: the daemon starts with the flags bh-zap uses and answers /JSON/core/view/version/ on 127.0.0.1.
zap_check() {
  local jar=/opt/bh/zap.jar home port key out v="" pid i
  [ -e "$jar" ] || { echo "MISS zap (no /opt/bh/zap.jar)"; return 1; }
  command -v java >/dev/null 2>&1 || { echo "MISS java"; return 1; }
  home=$(mktemp -d) || return 1
  port=$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
  key=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  java -Xmx512m -Djava.awt.headless=true -jar "$jar" -installdir "$(dirname "$(readlink -f "$jar")")" -daemon \
       -host 127.0.0.1 -port "$port" -dir "$home" -silent -notel -config api.key="$key" \
       -config start.checkForUpdates=false -config start.checkAddonUpdates=false >"$home/zap.out" 2>&1 &
  pid=$!
  for i in $(seq 1 120); do
    out=$(curl -s --noproxy '*' -m 3 -H "X-ZAP-API-Key: $key" "http://127.0.0.1:$port/JSON/core/view/version/") || out=""
    case "$out" in *'"version"'*) v=$out; break ;; esac
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  curl -s --noproxy '*' -m 5 -H "X-ZAP-API-Key: $key" "http://127.0.0.1:$port/JSON/core/action/shutdown/" >/dev/null
  for i in $(seq 1 15); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  kill -9 "$pid" 2>/dev/null
  if [ -n "$v" ]; then echo "ok   zap daemon $v"; rm -rf "$home"; return 0; fi
  echo "MISS zap daemon (no API answer, log: $home/zap.out)"; return 1
}
zap_check || miss=$((miss+1))
for b in chromium chromedriver; do
  if command -v "$b" >/dev/null 2>&1; then printf 'ok   %s (bh-zap --ajax)\n' "$b"; else printf 'MISS %s\n' "$b"; miss=$((miss+1)); fi
done
# bh-web text --clipboard: xclip reads the page's clipboard on the browser's virtual display.
if command -v xclip >/dev/null 2>&1; then echo "ok   xclip (bh-web text --clipboard)"; else echo "MISS xclip"; miss=$((miss+1)); fi
if [ -s /opt/bh/missing-packages.txt ]; then echo "apt packages absent from Kali repo:"; sed 's/^/  - /' /opt/bh/missing-packages.txt; fi
exit $miss
