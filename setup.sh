#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")"

say() {
  printf '\033[1;34m==>\033[0m %s\n' "$*"
}

warn() {
  printf '\033[1;33m[!]\033[0m %s\n' "$*"
}

install_system_packages() {
  if [ "$(uname)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
    brew install $3                                   # Homebrew runs as the normal user
    return
  fi
  local as_admin=""
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || return 1
    as_admin="sudo"
  fi
  if command -v apt-get >/dev/null 2>&1; then
    $as_admin apt-get update -qq && $as_admin apt-get install -y -qq $1
  elif command -v dnf >/dev/null 2>&1; then
    $as_admin dnf install -y -q $2
  else
    return 1
  fi
}

find_python() {
  for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1 \
       && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      echo "$candidate"
      return
    fi
  done
}

PY="${PYTHON:-$(find_python)}"

if [ -z "$PY" ]; then
  say "Python 3.10+ not found: installing it"
  install_system_packages "python3 python3-venv" "python3" "python@3.12" || true
  PY="$(find_python)"
fi

if [ -z "$PY" ]; then
  echo "Python 3.10+ is required and could not be installed automatically. Please install it and run ./setup.sh again."
  exit 1
fi

say "Using $($PY --version) at $(command -v "$PY")"
"$PY" -c 'import sqlite3; print("    sqlite", sqlite3.sqlite_version, "(bundled with Python - nothing to install)")'

if ! "$PY" -c 'import venv, ensurepip' 2>/dev/null; then
  say "Python's venv module is missing: installing it"
  python_version="$("$PY" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  install_system_packages "python3-venv python${python_version}-venv" "python3" "python@3.12" || true
fi

if ! "$PY" -c 'import venv, ensurepip' 2>/dev/null; then
  echo "Python's venv module could not be installed automatically (Debian/Ubuntu: sudo apt install python3-venv)."
  exit 1
fi

export PIP_CACHE_DIR="$PWD/.pip-cache"

if [ ! -x .venv/bin/python ]; then
  say "Creating virtualenv in ./.venv"
  "$PY" -m venv .venv
fi

say "Installing Python packages into ./.venv (see requirements.txt)"
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements.txt

mkdir -p data

if [ ! -f .env ]; then
  cp .env.example .env
fi

.venv/bin/python -c "from app.db import init_db; init_db(); print('    database ready: data/onboarding.db')"

if [ "${ONB_SEED_DEMO_USERS:-1}" = "1" ]; then
  say "Creating demo accounts (development only)"
  .venv/bin/python scripts/manage_users.py seed-demo
fi

if ! command -v tesseract >/dev/null 2>&1; then
  say "Installing the OCR engine (tesseract) - your computer may ask for your password"
  install_system_packages "tesseract-ocr" "tesseract" "tesseract" || true
fi

if command -v tesseract >/dev/null 2>&1; then
  say "OCR engine ready: $(tesseract --version 2>&1 | head -1)"
else
  warn "tesseract could not be installed automatically: photos of documents cannot be read (text PDFs still work)."
  warn "Install it yourself (Debian/Ubuntu: sudo apt install tesseract-ocr, macOS: brew install tesseract)."
fi

cat <<'MSG'

Setup complete. Next:
  ./run.sh            start mock providers + worker + API   (open http://127.0.0.1:8000)
MSG
