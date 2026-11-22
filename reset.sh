#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  echo "Run ./setup.sh first"
  exit 1
fi

rm -rf data/onboarding.db* data/uploads
mkdir -p data/uploads

.venv/bin/python -c "from app.db import init_db; init_db()"
.venv/bin/python scripts/manage_users.py seed-demo
echo "Clean slate ready. Start the app with ./run.sh"
