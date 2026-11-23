#!/bin/bash
# Trust the gate CA (mitmproxy) so TLS interception works for every tool, then drop to hunter.
set -euo pipefail
CA=/gate-ca/mitmproxy-ca-cert.pem
for _ in $(seq 1 30); do [ -s "$CA" ] && break; sleep 1; done
if [ -s "$CA" ]; then
  cp "$CA" /usr/local/share/ca-certificates/bh-gate.crt
  update-ca-certificates >/dev/null 2>&1 || true
else
  echo "entrypoint: gate CA not found at $CA — TLS through the gate will fail" >&2
fi
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export NODE_EXTRA_CA_CERTS=$SSL_CERT_FILE REQUESTS_CA_BUNDLE=$SSL_CERT_FILE CURL_CA_BUNDLE=$SSL_CERT_FILE
chown -R hunter:hunter /work 2>/dev/null || true
export HOME=/home/hunter USER=hunter
exec runuser -u hunter --preserve-environment -- "$@"
