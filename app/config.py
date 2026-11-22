import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("ONB_DATA_DIR", ROOT / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DB_URL = os.environ.get("ONB_DB_URL", f"sqlite:///{DATA_DIR / 'onboarding.db'}")
RULES_FILE = Path(os.environ.get("ONB_RULES_FILE", ROOT / "rules.yaml"))

API_URL = os.environ.get("ONB_API_URL", "http://127.0.0.1:8000")
MOCK_URL = os.environ.get("ONB_MOCK_URL", "http://127.0.0.1:8001")
WEBHOOK_SECRET = os.environ.get("ONB_WEBHOOK_SECRET", "dev-webhook-secret").encode()

DEFAULT_TOKENS_BY_ROLE = {"reviewer": "reviewer-token", "admin": "admin-token"}
ALLOW_DEFAULT_TOKENS = os.environ.get("ONB_ALLOW_DEFAULT_TOKENS", "1") == "1"


def configured_tokens() -> dict[str, str]:
    role_by_token = {}
    for role, default_token in DEFAULT_TOKENS_BY_ROLE.items():
        token = os.environ.get(f"ONB_TOKEN_{role.upper()}", default_token)
        if token and (token != default_token or ALLOW_DEFAULT_TOKENS):
            role_by_token[token] = role
    return role_by_token


TOKENS = configured_tokens()

MAX_UPLOAD_BYTES = int(os.environ.get("ONB_MAX_UPLOAD_BYTES", 5 * 1024 * 1024))

SECURE_COOKIES = os.environ.get("ONB_SECURE_COOKIES", "0") == "1"
DEMO_PASSWORD = os.environ.get("ONB_DEMO_PASSWORD", "Demo-Passw0rd!")
DEMO_STEP_SECONDS = float(os.environ.get("ONB_DEMO_STEP_SECONDS", "0") or 0)
