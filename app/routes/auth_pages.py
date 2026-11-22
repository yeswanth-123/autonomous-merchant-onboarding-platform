from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from .. import auth, web
from ..db import session_scope
from ..domain.rules import load_rules

router = APIRouter()


@router.get("/")
def root(request: Request):
    return RedirectResponse(web.home_for(web.current_principal(request)), status_code=303)


@router.get("/login")
def login_page(request: Request, next: str | None = None):
    principal = web.current_principal(request)
    if principal:
        return RedirectResponse(web.home_for(principal), status_code=303)
    return web.render(request, "auth/login.html", next_url=next or "", error=None, email="")


@router.post("/login")
async def login(request: Request):
    form = await web.checked_form(request)
    email, password, next_url = form.get("email", ""), form.get("password", ""), form.get("next", "")
    error_message, session_token, user_role = None, None, None
    with session_scope() as session:
        try:
            user = auth.authenticate(session, email, password)
            if user:
                session_token = auth.start_session(session, user)
                user_role = user.role
            else:
                error_message = "Invalid email or password."
        except auth.AuthError as auth_error:
            error_message = str(auth_error)
    if error_message:
        return web.render(request, "auth/login.html", status_code=401,
                          next_url=next_url, error=error_message, email=email)
    destination = web.safe_next(next_url, "/portal" if user_role == "merchant" else "/console")
    response = RedirectResponse(destination, status_code=303)
    web.set_session_cookie(response, session_token)
    response.delete_cookie(web.PRE_LOGIN_CSRF_COOKIE)
    return response


@router.get("/signup")
def signup_page(request: Request):
    principal = web.current_principal(request)
    if principal:
        return RedirectResponse(web.home_for(principal), status_code=303)
    return web.render(request, "auth/signup.html", error=None, values={})


@router.post("/signup")
async def signup(request: Request):
    form = await web.checked_form(request)
    form_values = {"full_name": form.get("full_name", ""), "email": form.get("email", "")}
    error_message = None
    if form.get("password") != form.get("confirm"):
        error_message = "The two passwords do not match."
    elif form.get("consent") != "on":
        error_message = "Please accept the privacy notice to create an account."
    session_token = None
    if not error_message:
        with session_scope() as session:
            try:
                user = auth.create_user(session, form_values["email"], form.get("password", ""), "merchant",
                                        form_values["full_name"], consent=True)
                session_token = auth.start_session(session, user)
            except auth.AuthError as auth_error:
                error_message = str(auth_error)
    if error_message:
        return web.render(request, "auth/signup.html", status_code=422, error=error_message, values=form_values)
    response = web.redirect("/portal", "Welcome! Your account is ready.")
    web.set_session_cookie(response, session_token)
    response.delete_cookie(web.PRE_LOGIN_CSRF_COOKIE)
    return response


@router.get("/retention-policy")
def retention_policy_page(request: Request):
    return web.render(request, "auth/retention_policy.html", retention=load_rules().get("retention", {}))


@router.post("/logout")
async def logout(request: Request):
    await web.checked_form(request)
    with session_scope() as session:
        auth.end_session(session, request.cookies.get(auth.SESSION_COOKIE))
    response = web.redirect("/login", "You have been signed out.", "info")
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return response
