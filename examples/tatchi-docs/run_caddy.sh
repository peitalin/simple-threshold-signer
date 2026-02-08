#!/bin/bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

get_caddy_app_data_dir() {
  caddy environ | awk -F= '$1=="caddy.AppDataDir"{print $2; exit}'
}

pubkey_hash_from_cert() {
  local cert_path="$1"
  openssl x509 -in "$cert_path" -noout -pubkey 2>/dev/null \
    | openssl pkey -pubin -outform der 2>/dev/null \
    | openssl sha256 2>/dev/null \
    | awk '{print $2}'
}

pubkey_hash_from_key() {
  local key_path="$1"
  openssl pkey -in "$key_path" -pubout -outform der 2>/dev/null \
    | openssl sha256 2>/dev/null \
    | awk '{print $2}'
}

cleanup_mismatched_certs() {
  if ! command -v openssl >/dev/null 2>&1; then
    return 0
  fi

  local app_data_dir="$1"
  local cert_root="$app_data_dir/certificates/local"
  if [[ -z "$app_data_dir" || ! -d "$cert_root" ]]; then
    return 0
  fi

  local cleaned=0
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    local dir="$cert_root/$host"
    local crt="$dir/$host.crt"
    local key="$dir/$host.key"
    [[ -f "$crt" && -f "$key" ]] || continue

    local cert_hash key_hash
    cert_hash="$(pubkey_hash_from_cert "$crt" || true)"
    key_hash="$(pubkey_hash_from_key "$key" || true)"
    if [[ -n "$cert_hash" && -n "$key_hash" && "$cert_hash" != "$key_hash" ]]; then
      echo "Detected mismatched TLS keypair for $host; clearing cached certificate..."
      rm -rf "$dir"
      cleaned=1
    fi
  done < <(
    awk '
      /^[^#[:space:]]/ && index($0, "{") > 0 {
        # skip global options block start
        if ($1 == "{") next
        for (i = 1; i <= NF; i++) {
          tok = $i
          if (tok ~ /^#/) break
          if (index(tok, "{") > 0) {
            sub(/\{.*/, "", tok)
            if (tok != "") print tok
            break
          }
          print tok
        }
      }
    ' "$SCRIPT_DIR/Caddyfile" \
      | awk '
        # strip :PORT when present (but avoid IPv6 bracket form)
        /^[^[]+:[0-9]+$/ { sub(/:[0-9]+$/, "", $0) }
        { print }
      ' \
      | sort -u
  )

  if [[ "$cleaned" == 1 ]]; then
    echo "Done clearing mismatched cached certificates."
  fi
}

# Ensure Caddy is installed
if ! command -v caddy >/dev/null 2>&1; then
  echo "Caddy not found. Please install Caddy (brew install caddy)" >&2
  exit 1
fi

# Stop any stale Caddy instances that may still be listening on 443 (dev convenience)
caddy stop 2>/dev/null || true
pkill -f "caddy run" 2>/dev/null || true

APP_DATA_DIR="$(get_caddy_app_data_dir || true)"
cleanup_mismatched_certs "${APP_DATA_DIR:-}"

# Validate config and print environment
echo "Validating Caddyfile..."
caddy validate --config Caddyfile || { echo "Caddyfile validation failed" >&2; exit 1; }

echo "Starting Caddy (debug enabled via global options)"

CADDY_PID=""
cleanup() {
  if [[ -n "${CADDY_PID:-}" ]]; then
    kill "$CADDY_PID" 2>/dev/null || true
    wait "$CADDY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

caddy run --config Caddyfile --adapter caddyfile --environ &
CADDY_PID="$!"

# Trust Caddy's local CA (best-effort) so tls internal works without browser warnings.
# `caddy trust` talks to the admin API, so we wait briefly for it to come up.
if command -v curl >/dev/null 2>&1; then
  for _ in $(seq 1 50); do
    if curl -fsS "http://localhost:2019/config/" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
fi
caddy trust --config Caddyfile --adapter caddyfile || true

wait "$CADDY_PID"
