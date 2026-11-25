#!/bin/bash
# Acceptance for the agent image: every expected binary answers. rc = number of missing tools.
miss=0
for b in claude node python3 jq curl git proxychains4 dig subfinder httpx-toolkit dnsx katana nuclei naabu \
         ffuf feroxbuster gobuster arjun sqlmap dalfox wafw00f whatweb nikto trufflehog gitleaks nmap sslscan semgrep; do
  if command -v "$b" >/dev/null 2>&1; then printf 'ok   %s\n' "$b"; else printf 'MISS %s\n' "$b"; miss=$((miss+1)); fi
done
# bh-browse: playwright importable by the isolated interpreter bh-agent uses, headless shell present and readable.
if python3 -I -c "import playwright.sync_api" 2>/dev/null; then echo "ok   playwright (python3 -I)"; else echo "MISS playwright"; miss=$((miss+1)); fi
shell=$(ls "${PLAYWRIGHT_BROWSERS_PATH:-/opt/ms-playwright}"/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell 2>/dev/null | head -1)
if [ -n "$shell" ] && [ -x "$shell" ]; then echo "ok   chrome-headless-shell"; else echo "MISS chrome-headless-shell"; miss=$((miss+1)); fi
if command -v certutil >/dev/null 2>&1; then echo "ok   certutil"; else echo "MISS certutil"; miss=$((miss+1)); fi
if [ -s /opt/bh/missing-packages.txt ]; then echo "apt packages absent from Kali repo:"; sed 's/^/  - /' /opt/bh/missing-packages.txt; fi
exit $miss
