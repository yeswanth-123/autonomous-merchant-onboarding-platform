import hashlib
import hmac
import secrets
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from . import auth, charts, config, filecrypt
from .db import session_scope
from .extraction import pipeline
from .security import mask_field

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
PRE_LOGIN_CSRF_COOKIE = "onb_csrf"

TONE_BY_VALUE = {
    "SUBMITTED": "info",
    "EXTRACTING": "info",
    "VERIFYING": "info",
    "NEEDS_INFO": "warn",
    "MANUAL_REVIEW": "orange",
    "APPROVED": "success",
    "ACTIVE": "success",
    "REJECTED": "danger",
    "PROVISIONING_FAILED": "danger",
    "EXPIRED": "muted",
    "WITHDRAWN": "muted",

    "VERIFIED": "success",
    "FAILED": "danger",
    "PENDING": "warn",
    "REQUESTED": "warn",
    "TIMED_OUT": "danger",
    "ERROR": "danger",
    "SUPERSEDED": "muted",

    "VALID": "success",
    "INVALID": "danger",
    "MISSING": "danger",
    "BLURRY": "danger",
    "LOW_CONF": "warn",
    "CONFLICT": "orange",

    "open": "orange",
    "resolved": "success",
    "dead": "danger",
    "pending": "warn",
    "leased": "info",
    "done": "success",
    "retried": "muted",
}
LABEL_OVERRIDES = {
    "NEEDS_INFO": "Needs info",
    "MANUAL_REVIEW": "Manual review",
    "PROVISIONING_FAILED": "Provisioning failed",
    "TIMED_OUT": "Timed out",
    "LOW_CONF": "Low confidence",
}


def _label_for(value):
    return LABEL_OVERRIDES.get(value, str(value).replace("_", " ").capitalize() if str(value).isupper() else value)


templates.env.globals.update(tone_for=lambda value: TONE_BY_VALUE.get(value, "muted"), label_for=_label_for,
                             chart_donut=charts.donut, chart_bars=charts.bars, tone_colors=charts.TONE_COLORS,
                             photo_guidance={"recommended_long_side": pipeline.PHOTO_RECOMMENDED_LONG_SIDE,
                                             "max_megabytes": config.MAX_UPLOAD_BYTES // (1024 * 1024)})
templates.env.filters["short_datetime"] = lambda value: (value or "")[:16].replace("T", " ")
templates.env.filters["time_only"] = lambda value: (value or "")[11:19]
templates.env.filters["mask_email"] = lambda value: mask_field("email", value)


class AuthRedirect(Exception):
    def __init__(self, destination: str):
        self.destination = destination


def current_principal(request: Request) -> auth.Principal | None:
    if hasattr(request.state, "principal"):
        return request.state.principal
    with session_scope() as session:
        principal = auth.principal_from_token(session, request.cookies.get(auth.SESSION_COOKIE))
    request.state.principal = principal
    return principal


def need_login(request: Request, minimum: str | None = None, merchant_only: bool = False) -> auth.Principal:
    principal = current_principal(request)
    if principal is None:
        next_url = request.url.path + (("?" + request.url.query) if request.url.query else "")
        raise AuthRedirect(f"/login?next={quote(next_url)}")
    if merchant_only and principal.role != "merchant":
        raise AuthRedirect("/console")
    if minimum and not principal.at_least(minimum):
        raise HTTPException(403, f"This page requires the '{minimum}' role.")
    return principal


def home_for(principal: auth.Principal | None) -> str:
    if principal is None:
        return "/login"
    return "/portal" if principal.role == "merchant" else "/console"


def safe_next(url: str | None, default: str) -> str:
    if url and url.startswith("/") and not url.startswith("//") and "\\" not in url:
        return url
    return default


def pre_login_csrf_token(request: Request) -> str:
    return request.cookies.get(PRE_LOGIN_CSRF_COOKIE) or secrets.token_urlsafe(24)


@lru_cache(maxsize=1)
def _flash_signing_key() -> bytes:
    return hashlib.sha256(b"onb-flash-v1" + filecrypt.load_master_key()).digest()


def flash_signature(message: str, tone: str) -> str:
    return hmac.new(_flash_signing_key(), f"{tone}|{message}".encode(), hashlib.sha256).hexdigest()[:32]


def flash_from_request(request: Request) -> tuple[str | None, str]:
    message, tone = request.query_params.get("msg"), request.query_params.get("tone", "success")
    signature = request.query_params.get("sig", "")
    if not message or not hmac.compare_digest(flash_signature(message, tone), signature):
        return None, tone
    return message, tone


def flash_url(url: str, message: str, tone: str = "success") -> str:
    return url + ("&" if "?" in url else "?") + (f"msg={quote(message)}&tone={quote(tone)}"
                                                 f"&sig={flash_signature(message, tone)}")


def render(request: Request, template_name: str, status_code: int = 200, **context):
    principal = current_principal(request)
    csrf_token = principal.csrf if principal else pre_login_csrf_token(request)
    flash_message, flash_tone = flash_from_request(request)
    response = templates.TemplateResponse(request, template_name, {
        "user": principal, "csrf": csrf_token, "flash_message": flash_message,
        "flash_tone": flash_tone, "current_path": request.url.path,
        **context}, status_code=status_code)
    if principal is None and PRE_LOGIN_CSRF_COOKIE not in request.cookies:
        response.set_cookie(PRE_LOGIN_CSRF_COOKIE, csrf_token, httponly=True, samesite="lax",
                            secure=config.SECURE_COOKIES, max_age=3600)
    return response


def redirect(url: str, message: str | None = None, tone: str = "success", status_code: int = 303):
    if message:
        url = flash_url(url, message, tone)
    return RedirectResponse(url, status_code=status_code)


async def checked_form(request: Request):
    form = await request.form()
    principal = current_principal(request)
    expected_token = principal.csrf if principal else request.cookies.get(PRE_LOGIN_CSRF_COOKIE)
    if not auth.csrf_ok(expected_token, form.get("csrf")):
        raise HTTPException(403, "Your session expired or the form was invalid. Please go back, reload and try again.")
    return form


def set_session_cookie(response, token: str):
    response.set_cookie(auth.SESSION_COOKIE, token, httponly=True, samesite="lax", secure=config.SECURE_COOKIES,
                        max_age=auth.SESSION_LIFETIME_HOURS * 3600, path="/")


def security_headers(response, path: str):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if not path.startswith("/static"):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Content-Security-Policy",
                                    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                    "script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    return response
