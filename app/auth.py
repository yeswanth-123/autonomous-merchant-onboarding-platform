import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import audit, clock, models
from .security import ROLE_RANK

ALL_ROLES = ("merchant", "reviewer", "admin")
STAFF_ROLES = ("reviewer", "admin")
SESSION_COOKIE = "onb_session"
SESSION_LIFETIME_HOURS = 12
IDLE_TIMEOUT_HOURS = 2
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")

SCRYPT_COST, SCRYPT_BLOCK_SIZE, SCRYPT_PARALLELISM = 2 ** 14, 8, 1
SCRYPT_KEY_LENGTH = 32
SCRYPT_MAX_MEMORY = 64 * 1024 * 1024


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived_key = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_COST, r=SCRYPT_BLOCK_SIZE, p=SCRYPT_PARALLELISM,
                                 dklen=SCRYPT_KEY_LENGTH, maxmem=SCRYPT_MAX_MEMORY)
    return "scrypt${}${}${}${}${}".format(SCRYPT_COST, SCRYPT_BLOCK_SIZE, SCRYPT_PARALLELISM,
                                          base64.b64encode(salt).decode(), base64.b64encode(derived_key).decode())


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        _scheme, cost, block_size, parallelism, salt, stored_key = stored_hash.split("$")
        candidate_key = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(cost), r=int(block_size),
                                       p=int(parallelism), dklen=SCRYPT_KEY_LENGTH, maxmem=SCRYPT_MAX_MEMORY)
        return hmac.compare_digest(candidate_key, base64.b64decode(stored_key))
    except Exception:
        return False


_UNKNOWN_USER_PASSWORD_HASH = hash_password("not-a-real-password")


MIN_PASSWORD_LENGTH = 10


def password_problems(password: str, email: str = "") -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"at least {MIN_PASSWORD_LENGTH} characters")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9\s]", password):
        problems.append("a special character such as ! @ # $ -")
    email_name = email.split("@")[0].lower()
    if email_name and len(email_name) >= 4 and email_name in password.lower():
        problems.append("must not contain your email name")
    return problems


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


class AuthError(Exception):
    pass


def create_user(session: Session, email: str, password: str, role: str = "merchant", full_name: str = "",
                consent: bool = True) -> models.User:
    email = normalize_email(email)
    if not EMAIL_PATTERN.match(email):
        raise AuthError("Please enter a valid email address.")
    if role not in ALL_ROLES:
        raise AuthError("Unknown role.")
    problems = password_problems(password, email)
    if problems:
        raise AuthError("Password needs: " + "; ".join(problems) + ".")
    if session.scalars(select(models.User).where(models.User.email == email)).first():
        raise AuthError("An account with this email already exists.")
    user = models.User(email=email, password_hash=hash_password(password), role=role, full_name=full_name.strip()[:120],
                       consented_at=clock.now() if consent else None)
    session.add(user)
    session.flush()
    audit.record(session, None, f"user:{user.id}", "USER_CREATED", payload={"role": role})
    return user


def authenticate(session: Session, email: str, password: str) -> models.User | None:
    user = session.scalars(select(models.User).where(models.User.email == normalize_email(email))).first()
    password_matches = verify_password(password, user.password_hash if user and user.password_hash
                                       else _UNKNOWN_USER_PASSWORD_HASH)
    if not (user and password_matches and not user.disabled):
        audit.record(session, None, f"user:{user.id if user else '?'}", "LOGIN_FAILED")
        return None
    user.last_login_at = clock.now()
    audit.record(session, None, f"user:{user.id}", "LOGIN_OK")
    return user


@dataclass
class Principal:
    user_id: int
    email: str
    role: str
    full_name: str
    csrf: str

    @property
    def is_staff(self) -> bool:
        return self.role in STAFF_ROLES

    def at_least(self, role: str) -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK[role]


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(session: Session, user: models.User) -> str:
    token = secrets.token_urlsafe(32)
    session.add(models.UserSession(token_hash=_hash_token(token), user_id=user.id, csrf=secrets.token_urlsafe(24),
                                   expires_at=clock.now() + timedelta(hours=SESSION_LIFETIME_HOURS)))
    return token


def principal_from_token(session: Session, token: str | None) -> Principal | None:
    if not token:
        return None
    session_row = session.scalars(select(models.UserSession).where(
        models.UserSession.token_hash == _hash_token(token))).first()
    if session_row is None:
        return None
    now = clock.now()
    user = session.get(models.User, session_row.user_id)
    if (session_row.expires_at < now or now - session_row.last_seen > timedelta(hours=IDLE_TIMEOUT_HOURS)
            or user is None or user.disabled):
        session.delete(session_row)
        return None
    if (now - session_row.last_seen).total_seconds() > 60:
        session_row.last_seen = now
    return Principal(user.id, user.email, user.role, user.full_name, session_row.csrf)


def end_session(session: Session, token: str | None):
    if token:
        session.execute(delete(models.UserSession).where(models.UserSession.token_hash == _hash_token(token)))


def purge_expired_sessions(session: Session) -> int:
    now = clock.now()
    result = session.execute(delete(models.UserSession).where(
        (models.UserSession.expires_at < now) |
        (models.UserSession.last_seen < now - timedelta(hours=IDLE_TIMEOUT_HOURS))))
    return result.rowcount or 0


def end_all_sessions(session: Session, user_id: int) -> int:
    result = session.execute(delete(models.UserSession).where(models.UserSession.user_id == user_id))
    return result.rowcount or 0


def user_by_email(session: Session, email: str) -> models.User:
    user = session.scalars(select(models.User).where(models.User.email == normalize_email(email))).first()
    if user is None:
        raise AuthError(f"No account with email {normalize_email(email)}.")
    return user


def _is_last_active_admin(session: Session, user: models.User) -> bool:
    if user.role != "admin" or user.disabled:
        return False
    active_admin_count = session.scalar(select(func.count()).select_from(models.User).where(
        models.User.role == "admin", models.User.disabled.is_(False))) or 0
    return active_admin_count <= 1


def set_user_disabled(session: Session, user: models.User, disabled: bool, actor: str) -> int:
    if disabled and _is_last_active_admin(session, user):
        raise AuthError("This is the last active admin account; create or enable another admin first.")
    user.disabled = disabled
    ended_sessions = end_all_sessions(session, user.id) if disabled else 0
    audit.record(session, None, actor, "USER_DISABLED" if disabled else "USER_ENABLED",
                 payload={"user": user.id, "role": user.role, "sessions_ended": ended_sessions})
    return ended_sessions


def change_role(session: Session, user: models.User, new_role: str, actor: str):
    if new_role not in ALL_ROLES:
        raise AuthError(f"Unknown role; choose one of {', '.join(ALL_ROLES)}.")
    if new_role == user.role:
        return
    if new_role != "admin" and _is_last_active_admin(session, user):
        raise AuthError("This is the last active admin account; create or enable another admin first.")
    previous_role, user.role = user.role, new_role
    end_all_sessions(session, user.id)
    audit.record(session, None, actor, "USER_ROLE_CHANGED",
                 payload={"user": user.id, "from": previous_role, "to": new_role})


def reset_password(session: Session, user: models.User, new_password: str, actor: str):
    problems = password_problems(new_password, user.email)
    if problems:
        raise AuthError("Password needs: " + "; ".join(problems) + ".")
    user.password_hash = hash_password(new_password)
    end_all_sessions(session, user.id)
    audit.record(session, None, actor, "PASSWORD_RESET", payload={"user": user.id})


def csrf_ok(expected_token: str | None, given_token: str | None) -> bool:
    return bool(expected_token) and bool(given_token) and hmac.compare_digest(expected_token, given_token)
