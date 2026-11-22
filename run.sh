#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  echo "Run ./setup.sh first"
  exit 1
fi

if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

API_PORT="${API_PORT:-8000}"
MOCK_PORT="${MOCK_PORT:-8001}"
export ONB_API_URL="${ONB_API_URL:-http://127.0.0.1:$API_PORT}"
export ONB_MOCK_URL="${ONB_MOCK_URL:-http://127.0.0.1:$MOCK_PORT}"

PIDS=()

cleanup() {
  echo
  echo "stopping..."
  kill "${PIDS[@]}" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

.venv/bin/python -c "from app.db import init_db; init_db()"

.venv/bin/python -m uvicorn mock_providers.main:app --port "$MOCK_PORT" --log-level warning &
PIDS+=($!)

.venv/bin/python -m app.worker &
PIDS+=($!)

.venv/bin/python -m uvicorn app.main:app --port "$API_PORT" --log-level warning &
PIDS+=($!)

echo "App:       $ONB_API_URL   (sign in: merchant@demo.local / reviewer@demo.local / admin@demo.local)"
echo "API docs:  $ONB_API_URL/docs"
echo "Mock log:  $ONB_MOCK_URL/mock/log"

wait
