import base64
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config

MAGIC = b"ONBF1"
NONCE_LENGTH = 12
WRAPPED_KEY_LENGTH = 32 + 16
TAG_LENGTH = 16
MASTER_KEY_FILE = config.DATA_DIR / ".master_key"
_KEY_WRAP_CONTEXT = b"onb-data-key"


class DecryptionError(Exception):
    pass


def load_master_key() -> bytes:
    key_from_env = os.environ.get("ONB_MASTER_KEY")
    if key_from_env:
        master_key = base64.urlsafe_b64decode(key_from_env.encode())
    else:
        if not MASTER_KEY_FILE.exists():
            file_descriptor = os.open(MASTER_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(file_descriptor, "wb") as key_file:
                key_file.write(AESGCM.generate_key(256))
        master_key = MASTER_KEY_FILE.read_bytes()
    if len(master_key) != 32:
        raise RuntimeError("master key must be exactly 32 bytes")
    return master_key


def aad_for(application_id: str, path: str | Path) -> bytes:
    return f"{application_id}/{Path(path).stem}".encode()


def encrypt_bytes(plaintext: bytes, aad: bytes) -> bytes:
    data_key = AESGCM.generate_key(256)
    content_nonce, wrap_nonce = os.urandom(NONCE_LENGTH), os.urandom(NONCE_LENGTH)
    wrapped_data_key = AESGCM(load_master_key()).encrypt(wrap_nonce, data_key, _KEY_WRAP_CONTEXT)
    ciphertext = AESGCM(data_key).encrypt(content_nonce, plaintext, aad)
    return MAGIC + wrap_nonce + wrapped_data_key + content_nonce + ciphertext


def decrypt_bytes(blob: bytes, aad: bytes) -> bytes:
    header_length = len(MAGIC) + NONCE_LENGTH + WRAPPED_KEY_LENGTH + NONCE_LENGTH
    if not blob.startswith(MAGIC) or len(blob) < header_length + TAG_LENGTH:
        raise DecryptionError("not an encrypted document")
    offset = len(MAGIC)
    wrap_nonce = blob[offset:offset + NONCE_LENGTH]
    offset += NONCE_LENGTH
    wrapped_data_key = blob[offset:offset + WRAPPED_KEY_LENGTH]
    offset += WRAPPED_KEY_LENGTH
    content_nonce = blob[offset:offset + NONCE_LENGTH]
    ciphertext = blob[offset + NONCE_LENGTH:]
    try:
        data_key = AESGCM(load_master_key()).decrypt(wrap_nonce, wrapped_data_key, _KEY_WRAP_CONTEXT)
        return AESGCM(data_key).decrypt(content_nonce, ciphertext, aad)
    except InvalidTag as error:
        raise DecryptionError("document failed authentication (wrong key, tampered or moved)") from error


def write_encrypted(path: Path, plaintext: bytes, aad: bytes) -> None:
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    file_descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(file_descriptor, "wb") as handle:
        handle.write(encrypt_bytes(plaintext, aad))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary_path, path)


def read_decrypted(path: str | Path, application_id: str) -> bytes:
    try:
        return decrypt_bytes(Path(path).read_bytes(), aad_for(application_id, path))
    except FileNotFoundError as error:
        raise DecryptionError("document file not found") from error
