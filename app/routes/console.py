from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import func, select

from .. import audit, filecrypt, models, services, web
from .. import metrics as metrics_module
from ..db import session_scope
from ..domain import engine as workflow
from ..domain import states
from ..security import mask_field

router = APIRouter(prefix="/console")
STAGES = ["Submitted", "Extracting", "Verifying", "Review", "Approved", "Active"]
STAGE_INDEX_BY_STATE = {states.SUBMITTED: 0, states.EXTRACTING: 1, states.NEEDS_INFO: 1, states.VERIFYING: 2,
                        states.MANUAL_REVIEW: 3, states.APPROVED: 4, states.PROVISIONING_FAILED: 4, states.ACTIVE: 5}


def require_staff(request: Request, minimum_role: str = "reviewer"):
    return web.need_login(request, minimum_role)


def audit_actor_label(principal) -> str:
    return f"{principal.role}:{principal.user_id}"


def _owner_label(session, application: models.Application) -> str:
    if not application.owner_id:
        return "demo / service"
    owner = session.get(models.User, application.owner_id)
    return mask_field("email", owner.email) if owner else "deleted user"


@router.get("")
def overview_page(request: Request):
    require_staff(request)
    with session_scope() as session:
        stats = metrics_module.compute(session)
        open_tasks = [{"id": task.id, "application_id": task.application_id, "reason": task.reason_code,
                       "priority": task.priority, "opened_at": task.opened_at.isoformat()}
                      for task in session.scalars(select(models.ReviewTask).where(models.ReviewTask.status == "open")
                                                  .order_by(models.ReviewTask.priority, models.ReviewTask.id).limit(6))]
        recent_applications = [services.application_summary(application) for application in session.scalars(
            select(models.Application).order_by(models.Application.created_at.desc()).limit(8))]
    in_progress_count = sum(stats["by_state"][state_name] for state_name in (
        states.SUBMITTED, states.EXTRACTING, states.VERIFYING, states.NEEDS_INFO, states.APPROVED))
    return web.render(request, "console/overview.html", stats=stats, open_tasks=open_tasks,
                      recent_applications=recent_applications, in_progress_count=in_progress_count,
                      count_by_state=stats["by_state"])


@router.get("/applications")
def applications_page(request: Request, state: str | None = None, q: str | None = None):
    require_staff(request)
    with session_scope() as session:
        query = select(models.Application).order_by(models.Application.created_at.desc()).limit(300)
        if state:
            query = query.where(models.Application.state == state)
        if q:
            query = query.where(models.Application.id.contains(q.strip().upper()))
        application_rows = []
        for application in session.scalars(query):
            summary = services.application_summary(application)
            summary["owner"] = _owner_label(session, application)
            application_rows.append(summary)
        count_by_state = dict(session.execute(select(models.Application.state, func.count())
                                              .group_by(models.Application.state)).all())
    return web.render(request, "console/applications.html", application_rows=application_rows,
                      all_states=states.ALL_STATES, selected_state=state, search_text=q or "",
                      count_by_state=count_by_state)


def _application_detail_context(principal, application_id: str, unmask: bool) -> dict:
    with session_scope() as session:
        application = session.get(models.Application, application_id)
        if application is None:
            raise HTTPException(404, "Application not found")
        if unmask and principal.at_least("reviewer") and not application.anonymised_at:
            audit.record(session, application_id, audit_actor_label(principal), "PII_UNMASKED")
        else:
            unmask = False
        detail = services.application_detail(session, application, unmask)
        detail["owner"] = None if not application.owner_id else _owner_label(session, application)
    return {"application": detail, "unmask": unmask, "audit_rows": list(reversed(detail["audit"])), "stages": STAGES,
            "stage_index": STAGE_INDEX_BY_STATE.get(detail["state"]), "is_ended": detail["state"] in states.TERMINAL,
            "can_decide": principal.at_least("reviewer"), "is_admin": principal.role == "admin"}


@router.get("/applications/{application_id}")
def application_page(request: Request, application_id: str, unmask: bool = False, fragment: bool = False):
    principal = require_staff(request)
    context = _application_detail_context(principal, application_id, unmask)
    return web.render(request, "console/_detail_body.html" if fragment else "console/application.html", **context)


@router.post("/applications/{application_id}/action")
async def decide_application(request: Request, application_id: str):
    principal = require_staff(request, "reviewer")
    form = await web.checked_form(request)
    try:
        with session_scope() as session:
            workflow.apply_event(session, application_id,
                                 {"type": "OperatorAction", "action": form.get("act"), "reason": form.get("reason", ""),
                                  "message": form.get("message", "")}, audit_actor_label(principal))
    except (ValueError, workflow.ConflictError) as error:
        return web.redirect(f"/console/applications/{application_id}", str(error), "danger")
    return web.redirect(f"/console/applications/{application_id}", "Action recorded.")


@router.get("/documents/{document_id}")
def view_document(request: Request, document_id: int):
    principal = require_staff(request, "reviewer")
    with session_scope() as session:
        document = session.get(models.Document, document_id)
        if document is None or not document.storage_path:
            raise HTTPException(404, "Document not available (structured payload or removed by retention policy)")
        try:
            file_bytes = services.read_document(document)
        except filecrypt.DecryptionError as error:
            raise HTTPException(410, str(error))
        audit.record(session, document.application_id, audit_actor_label(principal), "DOCUMENT_VIEWED",
                     payload={"doc_type": document.doc_type, "doc_id": document.id})
        content_type = services.CONTENT_TYPES.get(document.content_type or "", "application/octet-stream")
        display_name = document.filename
    return Response(file_bytes, media_type=content_type, headers={
        "Content-Disposition": f'inline; filename="{display_name}"',
        "X-Content-Type-Options": "nosniff",
    })


@router.get("/review")
def review_queue_page(request: Request):
    require_staff(request)
    with session_scope() as session:
        review_tasks = []
        for task in session.scalars(select(models.ReviewTask).where(models.ReviewTask.status == "open")
                                    .order_by(models.ReviewTask.priority, models.ReviewTask.id)):
            application = session.get(models.Application, task.application_id)
            review_tasks.append({"id": task.id, "application_id": task.application_id, "reason": task.reason_code,
                                 "priority": task.priority, "opened_at": task.opened_at.isoformat(),
                                 "context": task.context, "state": application.state})
    return web.render(request, "console/review.html", review_tasks=review_tasks)


@router.get("/dlq")
def dead_letters_page(request: Request):
    require_staff(request, "admin")
    with session_scope() as session:
        dead_jobs = [{"id": job.id, "type": job.type, "application_id": job.application_id, "attempts": job.attempts,
                      "error": job.last_error}
                     for job in session.scalars(select(models.Job).where(models.Job.status == "dead"))]
        stuck_application_ids = [application.id for application in session.scalars(
            select(models.Application).where(models.Application.state == states.PROVISIONING_FAILED))]
    return web.render(request, "console/dlq.html", dead_jobs=dead_jobs, stuck_application_ids=stuck_application_ids)


@router.post("/jobs/{job_id}/retry")
async def retry_dead_job_from_console(request: Request, job_id: int):
    principal = require_staff(request, "admin")
    await web.checked_form(request)
    try:
        with session_scope() as session:
            outcome = services.retry_dead_job(session, job_id, audit_actor_label(principal))
    except KeyError:
        raise HTTPException(404, "Job not found")
    except (ValueError, workflow.ConflictError) as error:
        return web.redirect("/console/dlq", str(error), "danger")
    return web.redirect("/console/dlq", f"Retried: {outcome}.")


@router.get("/metrics")
def metrics_page(request: Request):
    require_staff(request, "admin")
    with session_scope() as session:
        stats = metrics_module.compute(session)
    tone_by_state = {
        "VERIFYING": "info",
        "EXTRACTING": "info",
        "NEEDS_INFO": "warn",
        "MANUAL_REVIEW": "orange",
        "APPROVED": "success",
    }
    time_in_state_rows = []
    for state_name, visit_stats in stats["time_in_state"].items():
        time_in_state_rows.append((
            state_name,
            visit_stats["avg_s"],
            visit_stats["p95_s"],
            tone_by_state.get(state_name, "muted"),
        ))
    return web.render(request, "console/metrics.html", stats=stats, time_in_state_rows=time_in_state_rows)
