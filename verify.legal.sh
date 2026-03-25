#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-8123}"
LOG_FILE="/tmp/inventory_http_test.log"

cd "$ROOT_DIR"

DATABASE_URL='' PORT="$PORT" node server.js >"$LOG_FILE" 2>&1 &
SERVER_PID=$!

cleanup() {
  kill "$SERVER_PID" >/dev/null 2>&1 || true
  wait "$SERVER_PID" >/dev/null 2>&1 || true
}

trap cleanup EXIT

sleep 3

fetch_endpoint() {
  local label="$1"
  local url="$2"
  echo "--- ${label} ---"
  if ! curl -sS -D - "$url" | head -n 12; then
    echo
    echo "Request to $url failed. Server log:"
    sed -n '1,120p' "$LOG_FILE"
    exit 1
  fi
  echo
}

fetch_endpoint "TERMS" "http://127.0.0.1:${PORT}/api/legal/terms"
fetch_endpoint "PRIVACY" "http://127.0.0.1:${PORT}/api/legal/privacy"
