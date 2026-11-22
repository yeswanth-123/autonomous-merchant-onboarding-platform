from dataclasses import dataclass

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy import select

from .. import audit, auth, config, models, security, services
from .. import metrics as metrics_module
from ..db import session_scope
from ..domain import engine as workflow
from ..security import ROLE_RANK
from ..webhooks import BadSignature, MalformedCallback, handle_webhook

router = APIRouter()
UNSAFE_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class Actor:
    role: str
    user_id: int | None
    via: str
    label: str

    @property
    def is_staff(self) -> bool:
        return self.role in auth.STAFF_ROLES

    @property
    def is_trusted_client(self) -> bool:
        return self.via == "token" or self.is_staff


def actor_of(request: Request) -> Actor | None:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        role = security.role_for_token(authorization[7:])
        return Actor(role, None, "token", f"operator:{role}") if role else None
    session_token = request.cookies.get(auth.SESSION_COOKIE)
    if not session_token:
        return None
    with session_scope() as session:
        principal = auth.principal_from_token(session, session_token)
    if principal is None:
        return None
    if request.method in UNSAFE_HTTP_METHODS and not auth.csrf_ok(principal.csrf, request.headers.get("x-csrf-token")):
        raise HTTPException(403, "missing or invalid X-CSRF-Token header")
    return Actor(principal.role, principal.user_id, "session", f"{principal.role}:{principal.user_id}")


def need_actor(request: Request) -> Actor:
    actor = actor_of(request)
    if actor is None:
        raise HTTPException(401, "authentication required (Bearer token or login session)")
    return actor


def need_role(request: Request, minimum_role: str) -> Actor:
    actor = need_actor(request)
    if ROLE_RANK.get(actor.role, -1) < ROLE_RANK[minimum_role]:
        raise HTTPException(403, f"requires role '{minimum_role}'")
    return actor


def _translate_errors(operation):
    try:
        return operation()
    except KeyError:
        raise HTTPException(404, "not found")
    except workflow.ConflictError as error:
        raise HTTPException(409, str(error))
    except (services.ValidationFailed, ValueError) as error:
        raise HTTPException(422, str(error))


def _accessible_application(session, application_id: str, actor: Actor) -> models.Application:
    if actor.is_staff or actor.via == "token":
        application = session.get(models.Application, application_id)
        if application is None:
            raise KeyError(application_id)
        return application
    return services.owned_application(session, application_id, actor.user_id)


@router.post("/applications", status_code=201)
def create_application(request: Request, body: dict):
    actor = need_actor(request)

    def run_operation():
        with session_scope() as session:
            application, was_created = services.create_application(
                session, body, actor=actor.label, owner_id=actor.user_id,
                allow_scenarios=actor.is_trusted_client, allow_structured_documents=actor.is_trusted_client)
            return {"id": application.id, "state": application.state, "created": was_created,
                    "awaiting_documents": (application.flags or {}).get(services.AWAITING_DOCUMENTS_FLAG, [])}
    return _translate_errors(run_operation)


@router.patch("/applications/{application_id}")
@router.post("/applications/{application_id}/resubmit")
def resubmit(application_id: str, request: Request, body: dict):
    actor = need_actor(request)

    def run_operation():
        with session_scope() as session:
            _accessible_application(session, application_id, actor)
            application, changed = services.submit_changes(session, application_id, body.get("form"),
                                                           body.get("documents"), actor=actor.label,
                                                           allow_structured_documents=actor.is_trusted_client)
            return {"id": application.id, "state": application.state, "data_version": application.data_version,
                    "changed": changed}
    return _translate_errors(run_operation)


@router.post("/applications/{application_id}/documents/upload")
async def upload_document(
    application_id: str,
    request: Request,
    doc_type: str = Form(...),
    file: UploadFile = File(...),
):
    actor = need_actor(request)
    file_bytes = await file.read(config.MAX_UPLOAD_BYTES + 1)

    def run_operation():
        with session_scope() as session:
            _accessible_application(session, application_id, actor)
            uploaded_document = {"doc_type": doc_type, "file": (file.filename or "upload", file_bytes)}
            application, _changed = services.submit_changes(
                session, application_id, None, [uploaded_document], actor=actor.label)
            return {"id": application.id, "state": application.state, "data_version": application.data_version}
    return _translate_errors(run_operation)


@router.post("/applications/{application_id}/withdraw")
def withdraw(application_id: str, request: Request):
    actor = need_actor(request)

    def run_operation():
        with session_scope() as session:
            _accessible_application(session, application_id, actor)
            return {"id": application_id,
                    "state": services.withdraw_application(session, application_id, actor.label).state}
    return _translate_errors(run_operation)


@router.get("/applications/{application_id}/status")
def status(application_id: str, request: Request):
    actor = need_actor(request)

    def run_operation():
        with session_scope() as session:
            view = services.merchant_view(session, _accessible_application(session, application_id, actor))
            merchant_safe_keys = ("id", "state", "headline", "message", "stage", "missing_info", "merchant_id")
            return {key: view[key] for key in merchant_safe_keys}
    return _translate_errors(run_operation)


@router.get("/applications")
def list_applications(request: Request, state: str | None = None, limit: int = 100):
    need_role(request, "reviewer")
    with session_scope() as session:
        query = select(models.Application).order_by(models.Application.created_at.desc()).limit(limit)
        if state:
            query = query.where(models.Application.state == state)
        return [services.application_summary(application) for application in session.scalars(query)]


@router.get("/applications/{application_id}")
def get_application(application_id: str, request: Request, unmask: bool = False):
    actor = need_role(request, "reviewer")
    if unmask and ROLE_RANK.get(actor.role, -1) < ROLE_RANK["reviewer"]:
        raise HTTPException(403, "unmasking requires reviewer or admin")

    def run_operation():
        with session_scope() as session:
            application = session.get(models.Application, application_id)
            if application is None:
                raise KeyError(application_id)
            if unmask:
                audit.record(session, application_id, actor.label, "PII_UNMASKED")
            return services.application_detail(session, application, unmask)
    return _translate_errors(run_operation)


@router.get("/applications/{application_id}/audit")
def get_audit(application_id: str, request: Request):
    need_role(request, "reviewer")
    with session_scope() as session:
        return services.audit_trail(session, application_id)


@router.get("/review-tasks")
def review_tasks(request: Request, status: str = "open"):
    need_role(request, "reviewer")
    with session_scope() as session:
        return [{"id": task.id, "application_id": task.application_id, "reason": task.reason_code,
                 "priority": task.priority, "status": task.status, "opened_at": task.opened_at.isoformat(),
                 "context": task.context}
                for task in session.scalars(select(models.ReviewTask).where(models.ReviewTask.status == status)
                                            .order_by(models.ReviewTask.priority, models.ReviewTask.id))]


@router.post("/applications/{application_id}/operator-action")
def operator_action(application_id: str, request: Request, body: dict):
    actor = need_role(request, "reviewer")

    def run_operation():
        with session_scope() as session:
            operator_event = {"type": "OperatorAction", "action": body.get("action"), "reason": body.get("reason"),
                              "message": body.get("message")}
            application = workflow.apply_event(session, application_id, operator_event, actor.label)
            return {"id": application.id, "state": application.state}
    return _translate_errors(run_operation)


@router.get("/jobs")
def list_jobs(request: Request, status: str | None = None):
    need_role(request, "reviewer")
    with session_scope() as session:
        query = select(models.Job).order_by(models.Job.id.desc()).limit(200)
        if status:
            query = query.where(models.Job.status == status)
        return [{"id": job.id, "type": job.type, "application_id": job.application_id, "status": job.status,
                 "attempts": job.attempts, "max_attempts": job.max_attempts, "last_error": job.last_error,
                 "run_at": job.run_at.isoformat()} for job in session.scalars(query)]


@router.post("/jobs/{job_id}/retry")
def retry_job(job_id: int, request: Request):
    actor = need_role(request, "reviewer")

    def run_operation():
        with session_scope() as session:
            outcome = services.retry_dead_job(session, job_id, actor.label)
            return {"id": job_id, "status": session.get(models.Job, job_id).status, "outcome": outcome}
    return _translate_errors(run_operation)


@router.get("/metrics")
def get_metrics(request: Request):
    need_role(request, "reviewer")
    with session_scope() as session:
        return metrics_module.compute(session)


@router.post("/admin/retention/run")
def run_retention_now(request: Request):
    actor = need_role(request, "admin")
    from ..retention import run_retention
    with session_scope() as session:
        return run_retention(session, actor=actor.label)


@router.get("/health")
def health():
    return {"ok": True}


@router.post("/webhooks/{provider}")
async def webhook(provider: str, request: Request):
    raw_body = await request.body()
    signature = request.headers.get("x-signature")
    rejection = None
    with session_scope() as session:
        try:
            result = handle_webhook(session, provider, raw_body, signature)
        except BadSignature:
            rejection = JSONResponse({"error": "bad signature"}, status_code=401)
        except MalformedCallback as error:
            rejection = JSONResponse({"error": f"malformed callback: {error}"}, status_code=400)
    return rejection or result
