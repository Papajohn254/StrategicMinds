#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PORT=${PORT:-8099}
BASE_URL=${BASE_URL:-http://localhost:${PORT}}
DB_PATH=${DB_PATH:-"${ROOT_DIR}/data/test.db"}
LOG_FILE=${LOG_FILE:-"${ROOT_DIR}/data/test-server.log"}

command -v curl >/dev/null 2>&1 || { echo "curl is required"; exit 1; }
command -v sqlite3 >/dev/null 2>&1 || { echo "sqlite3 is required"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 1; }

if curl -sf "${BASE_URL}/api/public/branches" >/dev/null 2>&1; then
  echo "Port ${PORT} is already in use. Set PORT to a free port and retry."
  exit 1
fi

rm -f "${DB_PATH}"
mkdir -p "$(dirname "${DB_PATH}")"

cleanup(){
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

PORT="${PORT}" DB_PATH="${DB_PATH}" node "${ROOT_DIR}/server.js" >"${LOG_FILE}" 2>&1 &
SERVER_PID=$!
sleep 0.25
if ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
  echo "Server process exited early. Check ${LOG_FILE}"
  exit 1
fi

ready=0
for _ in {1..40}; do
  if curl -sf "${BASE_URL}/api/public/branches" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.25
done

if [[ "${ready}" != "1" ]]; then
  echo "Server failed to start. Check ${LOG_FILE}"
  exit 1
fi

ADMIN_EMAIL="admin@test.local"
ADMIN_PASS="Admin1234"

SETUP_RESP=$(curl -s -w "HTTP_STATUS:%{http_code}" -X POST "${BASE_URL}/api/setup" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Test Admin\",\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASS}\"}")
SETUP_BODY=${SETUP_RESP%HTTP_STATUS:*}
SETUP_STATUS=${SETUP_RESP##*HTTP_STATUS:}
if [[ "${SETUP_STATUS}" != "200" ]]; then
  if echo "${SETUP_BODY}" | grep -q "Setup already completed"; then
    echo "Setup already completed. Using existing admin."
  else
    echo "Setup failed (${SETUP_STATUS}): ${SETUP_BODY}"
    exit 1
  fi
fi

LOGIN_RESP=$(curl -s -w "HTTP_STATUS:%{http_code}" -X POST "${BASE_URL}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASS}\"}")
LOGIN_BODY=${LOGIN_RESP%HTTP_STATUS:*}
LOGIN_STATUS=${LOGIN_RESP##*HTTP_STATUS:}
if [[ "${LOGIN_STATUS}" != "200" ]]; then
  echo "Admin login failed (${LOGIN_STATUS}): ${LOGIN_BODY}"
  exit 1
fi

ADMIN_TOKEN=$(printf "%s" "${LOGIN_BODY}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

BRANCH_ID=$(curl -sf "${BASE_URL}/api/public/branches" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')

VENDOR_EMAIL="vendor@test.local"
VENDOR_PASS="Vendor1234"

curl -sf -X POST "${BASE_URL}/api/auth/vendor-register" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Vendor One\",\"email\":\"${VENDOR_EMAIL}\",\"password\":\"${VENDOR_PASS}\",\"role\":\"supplier\",\"branch_id\":${BRANCH_ID},\"phone\":\"0700000000\"}" >/dev/null

VENDOR_ID=$(sqlite3 "${DB_PATH}" "SELECT id FROM users WHERE email='${VENDOR_EMAIL}';")
SUPPLIER_ID=$(sqlite3 "${DB_PATH}" "SELECT supplier_id FROM users WHERE email='${VENDOR_EMAIL}';")

if [[ -z "${VENDOR_ID}" || -z "${SUPPLIER_ID}" ]]; then
  echo "Vendor registration failed (missing vendor or supplier)."
  exit 1
fi

curl -sf -X PUT "${BASE_URL}/api/users/${VENDOR_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"status\":\"active\"}" >/dev/null

VENDOR_LOGIN_RESP=$(curl -s -w "HTTP_STATUS:%{http_code}" -X POST "${BASE_URL}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${VENDOR_EMAIL}\",\"password\":\"${VENDOR_PASS}\"}")
VENDOR_LOGIN_BODY=${VENDOR_LOGIN_RESP%HTTP_STATUS:*}
VENDOR_LOGIN_STATUS=${VENDOR_LOGIN_RESP##*HTTP_STATUS:}
if [[ "${VENDOR_LOGIN_STATUS}" != "200" ]]; then
  echo "Vendor login failed (${VENDOR_LOGIN_STATUS}): ${VENDOR_LOGIN_BODY}"
  exit 1
fi

VENDOR_TOKEN=$(printf "%s" "${VENDOR_LOGIN_BODY}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

PRODUCT_ID=$(curl -sf -X POST "${BASE_URL}/api/products" \
  -H "Authorization: Bearer ${VENDOR_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Test Rice\",\"category\":\"Food\",\"price\":120,\"cost_price\":90,\"quantity\":40,\"supplier_id\":${SUPPLIER_ID},\"is_published\":1}" | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl -sf -X POST "${BASE_URL}/api/purchase-orders" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"supplier_id\":${SUPPLIER_ID},\"product_id\":${PRODUCT_ID},\"qty\":10,\"eta_date\":\"2026-03-25\",\"branch_id\":${BRANCH_ID}}" >/dev/null

PO_COUNT=$(sqlite3 "${DB_PATH}" "SELECT COUNT(*) FROM purchase_orders WHERE supplier_id=${SUPPLIER_ID};")
if [[ "${PO_COUNT}" -lt 1 ]]; then
  echo "Purchase order not found in DB."
  exit 1
fi

INBOX_COUNT=$(curl -sf "${BASE_URL}/api/vendor/purchase-orders" \
  -H "Authorization: Bearer ${VENDOR_TOKEN}" | \
  python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')

if [[ "${INBOX_COUNT}" -lt 1 ]]; then
  echo "Vendor purchase order inbox returned empty."
  exit 1
fi

ANALYTICS_PRODUCTS=$(curl -sf "${BASE_URL}/api/vendor/analytics" \
  -H "Authorization: Bearer ${VENDOR_TOKEN}" | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["total_products"])')

if [[ "${ANALYTICS_PRODUCTS}" -lt 1 ]]; then
  echo "Vendor analytics did not count products."
  exit 1
fi

ADMIN_COUNT=$(sqlite3 "${DB_PATH}" "SELECT COUNT(*) FROM users WHERE email='${ADMIN_EMAIL}';")
VENDOR_STATUS=$(sqlite3 "${DB_PATH}" "SELECT status FROM users WHERE email='${VENDOR_EMAIL}';")
PRODUCT_OWNER=$(sqlite3 "${DB_PATH}" "SELECT owner_user_id FROM products WHERE id=${PRODUCT_ID};")

if [[ "${ADMIN_COUNT}" -ne 1 ]]; then
  echo "Admin user missing in DB."
  exit 1
fi
if [[ "${VENDOR_STATUS}" != "active" ]]; then
  echo "Vendor status not active in DB."
  exit 1
fi
if [[ "${PRODUCT_OWNER}" -ne "${VENDOR_ID}" ]]; then
  echo "Product owner mismatch in DB."
  exit 1
fi

echo "Full test completed successfully."
