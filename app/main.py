from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import web
from .db import init_db
from .routes import api, auth_pages, console, portal


@asynccontextmanager
async def lifespan(_application):
    init_db()
    yield


app = FastAPI(title="Merchant Onboarding Platform", lifespan=lifespan)
app.include_router(auth_pages.router)
app.include_router(portal.router)
app.include_router(console.router)
app.include_router(api.router)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


@app.exception_handler(web.AuthRedirect)
async def _redirect_to_login(request: Request, redirect: web.AuthRedirect):
    return RedirectResponse(redirect.destination, status_code=303)


@app.exception_handler(HTTPException)
async def _render_http_error(request: Request, error: HTTPException):
    wants_html = "text/html" in request.headers.get("accept", "") and not request.url.path.startswith(("/webhooks",))
    if wants_html and error.status_code in (403, 404, 410, 422):
        return web.templates.TemplateResponse(request, "error.html", {
            "user": web.current_principal(request), "csrf": "", "flash_message": None, "flash_tone": "",
            "current_path": request.url.path, "code": error.status_code, "detail": error.detail},
            status_code=error.status_code)
    return JSONResponse({"detail": error.detail}, status_code=error.status_code,
                        headers=getattr(error, "headers", None))


@app.middleware("http")
async def _add_security_headers(request: Request, call_next):
    response = await call_next(request)
    return web.security_headers(response, request.url.path)
