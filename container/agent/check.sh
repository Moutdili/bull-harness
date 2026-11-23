#!/bin/bash
# Acceptance for the agent image: every expected binary answers. rc = number of missing tools.
miss=0
for b in claude node python3 jq curl git proxychains4 dig subfinder httpx-toolkit dnsx katana nuclei naabu \
         ffuf feroxbuster gobuster arjun sqlmap dalfox wafw00f whatweb nikto trufflehog gitleaks nmap sslscan semgrep; do
  if command -v "$b" >/dev/null 2>&1; then printf 'ok   %s\n' "$b"; else printf 'MISS %s\n' "$b"; miss=$((miss+1)); fi
done
if [ -s /opt/bh/missing-packages.txt ]; then echo "apt packages absent from Kali repo:"; sed 's/^/  - /' /opt/bh/missing-packages.txt; fi
exit $miss
