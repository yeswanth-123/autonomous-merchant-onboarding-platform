import hashlib
import hmac
import json
import os
import re

from cryptography.fernet import Fernet

from . import config

_FERNET_KEY_FILE = config.DATA_DIR / ".fernet_key"


def _load_fernet_key() -> bytes:
    key_from_env = os.environ.get("ONB_FERNET_KEY")
    if key_from_env:
        return key_from_env.encode()
    if not _FERNET_KEY_FILE.exists():
        _FERNET_KEY_FILE.write_bytes(Fernet.generate_key())
        os.chmod(_FERNET_KEY_FILE, 0o600)
    return _FERNET_KEY_FILE.read_bytes()


_fernet = Fernet(_load_fernet_key())


def encrypt_json(value) -> str:
    return _fernet.encrypt(json.dumps(value, default=str).encode()).decode()


def decrypt_json(token: str | None):
    if not token:
        return None
    return json.loads(_fernet.decrypt(token.encode()).decode())


def _hash_pepper() -> bytes:
    from . import filecrypt
    return hashlib.sha256(b"onb-pepper-v1" + filecrypt.load_master_key()).digest()


def stable_hash(*parts) -> str:
    message = "|".join("" if part is None else str(part).strip().upper() for part in parts)
    return hmac.new(_hash_pepper(), message.encode(), hashlib.sha256).hexdigest()


def mask_pan(pan: str) -> str:
    return pan[:5] + "****" + pan[-1:] if pan and len(pan) == 10 else _mask_generic(pan)


def mask_gstin(gstin: str) -> str:
    return gstin[:2] + "*" * (len(gstin) - 5) + gstin[-3:] if gstin and len(gstin) == 15 else _mask_generic(gstin)


def mask_account(account_number: str) -> str:
    return "X" * max(len(account_number) - 4, 0) + account_number[-4:] if account_number else account_number


def _mask_generic(text):
    if not text:
        return text
    return text[:1] + "*" * max(len(text) - 2, 0) + text[-1:] if len(text) > 2 else "**"


_MASKERS_BY_FIELD = {"pan": mask_pan, "gstin": mask_gstin, "bank_account": mask_account}


def mask_field(field_name: str, value) -> str | None:
    if value is None:
        return None
    text = str(value)
    if field_name in _MASKERS_BY_FIELD:
        return _MASKERS_BY_FIELD[field_name](text)
    if field_name == "email":
        local_part, _, domain = text.partition("@")
        return (local_part[:1] + "***@" + domain) if domain else _mask_generic(text)
    if field_name == "phone":
        return "******" + text[-4:]
    return text


_PAN_PATTERN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_GSTIN_PATTERN = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b")
_ACCOUNT_PATTERN = re.compile(r"\b\d{9,18}\b")


def redact_text(text: str) -> str:
    text = _GSTIN_PATTERN.sub(lambda match: mask_gstin(match.group()), text)
    text = _PAN_PATTERN.sub(lambda match: mask_pan(match.group()), text)
    return _ACCOUNT_PATTERN.sub(lambda match: mask_account(match.group()), text)


def redact(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


def sign(body: bytes, secret: bytes | None = None) -> str:
    return hmac.new(secret or config.WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()


def verify_signature(body: bytes, signature: str | None) -> bool:
    return bool(signature) and hmac.compare_digest(sign(body), signature)


ROLE_RANK = {"merchant": 0, "reviewer": 1, "admin": 2}


def role_for_token(token: str | None) -> str | None:
    return config.TOKENS.get(token or "")
