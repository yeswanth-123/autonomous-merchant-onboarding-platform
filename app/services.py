import hashlib
import io
import secrets

from PIL import Image, UnidentifiedImageError
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, clock, config, filecrypt, models
from .domain import engine as workflow
from .domain import states
from .domain.rules import load_rules
from .extraction.pipeline import (DOC_FIELDS, DOC_LABEL, PHOTO_MIN_LONG_SIDE, PHOTO_RECOMMENDED_LONG_SIDE,
                                  effective_documents, load_form)
from .extraction.validators import normalize_identifier, normalize_name
from .security import decrypt_json, encrypt_json, mask_field, stable_hash

DOC_TYPES = set(DOC_FIELDS)
IDENTIFIER_FORM_FIELDS = ("pan", "gstin", "ifsc", "bank_account")
_FILE_SIGNATURES = {b"%PDF": ("pdf", ".pdf"), b"\x89PNG": ("png", ".png"), b"\xff\xd8\xff": ("jpg", ".jpg")}
CONTENT_TYPES = {"pdf": "application/pdf", "png": "image/png", "jpg": "image/jpeg"}
SAFE_RESULT_KEYS = ("risk", "score", "penny_drop")
DEAD_JOB_RETRY_REASON = "retried from failed jobs"
DEAD_JOB_RECOVERY_ACTIONS = {
    "CREATE_MERCHANT": (states.PROVISIONING_FAILED, "PROVISIONING_FAILED", "retry_provisioning"),
    "START_VERIFICATIONS": (states.MANUAL_REVIEW, "PROVIDER_ERROR", "reverify"),
    "EXTRACT_DOCUMENTS": (states.MANUAL_REVIEW, "EXTRACTION_FAILED", "retry_extraction"),
}
DEAD_JOB_REQUEUE_STATES = {
    "CREATE_MERCHANT": (states.APPROVED,),
    "START_VERIFICATIONS": (states.VERIFYING,),
    "EXTRACT_DOCUMENTS": (states.SUBMITTED, states.EXTRACTING),
}


class ValidationFailed(Exception):
    pass


def safe_result(provider_data: dict | None) -> dict:
    return {key: value for key, value in (provider_data or {}).items() if key in SAFE_RESULT_KEYS}


def _clean_form(form: dict) -> dict:
    cleaned = {}
    for field_name, value in (form or {}).items():
        if value is None:
            continue
        value = str(value).strip()
        cleaned[field_name] = normalize_identifier(value) if field_name in IDENTIFIER_FORM_FIELDS else value
    return cleaned


def _save_file(application_id: str, file_bytes: bytes) -> tuple[str, str, str, str]:
    if len(file_bytes) > config.MAX_UPLOAD_BYTES:
        raise ValidationFailed("file too large (max %d MB)" % (config.MAX_UPLOAD_BYTES // 1024 // 1024))
    file_type = next((type_info for signature, type_info in _FILE_SIGNATURES.items()
                      if file_bytes.startswith(signature)), None)
    if file_type is None:
        raise ValidationFailed("unsupported file type (PDF, PNG or JPEG only)")
    content_type, extension = file_type
    if content_type in ("png", "jpg"):
        _check_photo_size(file_bytes)
    application_folder = config.UPLOAD_DIR / application_id
    application_folder.mkdir(parents=True, exist_ok=True)
    path = application_folder / f"{secrets.token_hex(12)}.enc"
    filecrypt.write_encrypted(path, file_bytes, filecrypt.aad_for(application_id, path))
    return str(path), hashlib.sha256(file_bytes).hexdigest(), content_type, extension


def _check_photo_size(file_bytes: bytes):
    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            long_side = max(image.size)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, ValueError):
        return
    if long_side < PHOTO_MIN_LONG_SIDE:
        raise ValidationFailed(
            f"photo is too small to read ({long_side} pixels on the long side). Please upload a photo of at least "
            f"{PHOTO_MIN_LONG_SIDE} pixels, ideally "
            f"{PHOTO_RECOMMENDED_LONG_SIDE[0]} to {PHOTO_RECOMMENDED_LONG_SIDE[1]}")


def read_document(document: models.Document) -> bytes:
    if document.purged_at or not document.storage_path:
        raise filecrypt.DecryptionError("document was removed under the retention policy")
    return filecrypt.read_decrypted(document.storage_path, document.application_id)


def _add_document(session: Session, application_id: str, data_version: int, document_spec: dict,
                  allow_structured_documents: bool) -> models.Document:
    doc_type = document_spec.get("doc_type")
    if doc_type not in DOC_TYPES:
        raise ValidationFailed(f"doc_type must be one of {sorted(DOC_TYPES)}")
    if "file" not in document_spec and not allow_structured_documents:
        raise ValidationFailed("please upload the document as a PDF, PNG or JPEG file "
                               "(structured document data is accepted from staff and service clients only)")
    if "file" in document_spec:
        _original_filename, file_bytes = document_spec["file"]
        try:
            path, digest, content_type, extension = _save_file(application_id, file_bytes)
        except ValidationFailed as error:
            raise ValidationFailed(f"{DOC_LABEL[doc_type]}: {error}") from error
        document = models.Document(application_id=application_id, data_version=data_version, doc_type=doc_type,
                                   filename=f"{doc_type.lower()}{extension}", storage_path=path,
                                   content_type=content_type, sha256=digest)
    else:
        payload = {"fields": document_spec.get("fields") or {}}
        if document_spec.get("image_quality") is not None:
            payload["image_quality"] = float(document_spec["image_quality"])
        document = models.Document(application_id=application_id, data_version=data_version, doc_type=doc_type,
                                   filename=f"{doc_type.lower()}.json", payload_enc=encrypt_json(payload),
                                   sha256=stable_hash(str(payload)))
    session.add(document)
    session.flush()
    return document


def _check_business_type(form: dict):
    business_types = load_rules().business_types
    if form.get("business_type") not in business_types:
        raise ValidationFailed(f"business_type must be one of {business_types}")


def _set_identity_columns(application: models.Application, form: dict):
    application.business_type = form.get("business_type", application.business_type or "company")
    application.legal_name_norm = normalize_name(form.get("legal_name", ""))
    application.pincode = form.get("pincode", "")


def create_application(session: Session, payload: dict, actor: str = "merchant", owner_id: int | None = None,
                       allow_scenarios: bool = True, allow_structured_documents: bool = True
                       ) -> tuple[models.Application, bool]:
    external_ref = payload.get("external_ref")
    if external_ref:
        existing_application = session.scalars(select(models.Application).where(
            models.Application.external_ref == external_ref)).first()
        if existing_application:
            return existing_application, False
    form = _clean_form(payload.get("form") or {})
    if payload.get("business_type"):
        form.setdefault("business_type", payload["business_type"])
    form.setdefault("business_type", "company")
    _check_business_type(form)
    application = models.Application(
        id="APP-" + secrets.token_hex(4).upper(), external_ref=external_ref, state=states.SUBMITTED, owner_id=owner_id,
        state_entered_at=clock.now(),
        scenarios=(payload.get("scenarios") or {}) if allow_scenarios else {})
    _set_identity_columns(application, form)
    session.add(application)
    session.flush()
    session.add(models.ApplicationVersion(
        application_id=application.id,
        data_version=1,
        form_data_enc=encrypt_json(form),
        form_hash=stable_hash(str(sorted(form.items()))),
        created_by=actor,
    ))
    for document_spec in payload.get("documents") or []:
        _add_document(session, application.id, 1, document_spec, allow_structured_documents)
    audit.record(session, application.id, actor, "APPLICATION_SUBMITTED", None, states.SUBMITTED,
                 {"documents": [document_spec.get("doc_type") for document_spec in payload.get("documents") or []]})
    if _hold_until_documents_complete(session, application, form, actor):
        return application, True
    workflow.enqueue(session, "EXTRACT_DOCUMENTS", application.id, {"data_version": 1},
                     idempotency_key=f"extract:{application.id}:1")
    return application, True


AWAITING_DOCUMENTS_FLAG = "awaiting_documents"


def missing_required_documents(session: Session, application: models.Application, form: dict) -> list[str]:
    session.flush()
    uploaded = effective_documents(session, application.id, application.data_version)
    required = load_rules().required_documents(form.get("business_type", application.business_type))
    return [doc_type for doc_type in required if doc_type not in uploaded]


def _hold_until_documents_complete(session: Session, application: models.Application, form: dict, actor: str) -> bool:
    missing_doc_types = missing_required_documents(session, application, form)
    flags = dict(application.flags or {})
    if not missing_doc_types:
        if AWAITING_DOCUMENTS_FLAG in flags:
            flags.pop(AWAITING_DOCUMENTS_FLAG)
            application.flags = flags
            application.missing_info = []
            audit.record(session, application.id, actor, "DOCUMENTS_COMPLETE")
        return False
    flags[AWAITING_DOCUMENTS_FLAG] = missing_doc_types
    application.flags = flags
    application.missing_info = [f"Upload your {DOC_LABEL[doc_type]}" for doc_type in missing_doc_types]
    audit.record(session, application.id, actor, "AWAITING_DOCUMENTS", payload={"missing": missing_doc_types})
    return True


def is_awaiting_documents(application: models.Application) -> bool:
    return application.state == states.SUBMITTED and AWAITING_DOCUMENTS_FLAG in (application.flags or {})


def submit_changes(session: Session, application_id: str, form_patch: dict | None, documents: list[dict] | None,
                   actor: str = "merchant", allow_structured_documents: bool = True) -> tuple[models.Application, bool]:
    application = session.get(models.Application, application_id)
    if application is None:
        raise KeyError(application_id)
    if application.state in states.TERMINAL:
        raise workflow.ConflictError(f"application is {application.state}; submit a new application")
    if application.anonymised_at is not None:
        raise workflow.ConflictError("this application's data was anonymised under the retention policy; "
                                     "submit a new application")
    old_form = load_form(session, application)
    patch = _clean_form(form_patch or {})
    new_form = {**old_form, **patch}
    if "business_type" in patch:
        _check_business_type(new_form)
    changed_fields = {field_name for field_name in patch if patch[field_name] != old_form.get(field_name)}
    new_documents = documents or []
    if not changed_fields and not new_documents:
        return application, False
    application.data_version += 1
    session.add(models.ApplicationVersion(application_id=application.id, data_version=application.data_version,
                                          form_data_enc=encrypt_json(new_form),
                                          form_hash=stable_hash(str(sorted(new_form.items()))), created_by=actor))
    for document_spec in new_documents:
        _add_document(session, application.id, application.data_version, document_spec, allow_structured_documents)
        changed_fields.add(f"doc:{document_spec.get('doc_type')}")
    _set_identity_columns(application, new_form)
    if is_awaiting_documents(application) and _hold_until_documents_complete(session, application, new_form, actor):
        return application, True
    data_changed_event = {"type": "DataChanged", "changed_fields": sorted(changed_fields)}
    workflow.apply_event(session, application.id, data_changed_event, actor)
    return application, True


def withdraw_application(session: Session, application_id: str, actor: str = "merchant") -> models.Application:
    return workflow.apply_event(session, application_id, {"type": "Withdraw"}, actor)


def retry_dead_job(session: Session, job_id: int, actor: str) -> str:
    job = session.get(models.Job, job_id)
    if job is None:
        raise KeyError(job_id)
    if job.status != "dead":
        raise workflow.ConflictError("only dead jobs can be retried")
    application = session.get(models.Application, job.application_id) if job.application_id else None
    if application is None:
        _requeue(job)
        return f"{job.type} job re-queued"
    required_state, review_reason, recovery_action = DEAD_JOB_RECOVERY_ACTIONS.get(job.type, (None, None, None))
    has_matching_open_review = review_reason is not None and session.scalars(select(models.ReviewTask).where(
        models.ReviewTask.application_id == application.id, models.ReviewTask.status == "open",
        models.ReviewTask.reason_code == review_reason)).first() is not None
    if application.state == required_state and has_matching_open_review:
        job.status = "retried"
        audit.record(session, application.id, actor, "DEAD_JOB_RETRIED",
                     payload={"job_id": job.id, "type": job.type, "recovery_action": recovery_action})
        workflow.apply_event(session, application.id, {"type": "OperatorAction", "action": recovery_action,
                                                       "reason": DEAD_JOB_RETRY_REASON}, actor)
        return f"{application.id}: ran '{recovery_action}'"
    if application.state in DEAD_JOB_REQUEUE_STATES.get(job.type, ()):
        _requeue(job)
        audit.record(session, application.id, actor, "DEAD_JOB_RETRIED", payload={"job_id": job.id, "type": job.type})
        return f"{job.type} job re-queued"
    raise workflow.ConflictError(f"{application.id} has moved on (state {application.state}); "
                                 "decide on it from the application page instead")


def _requeue(job: models.Job):
    job.status, job.attempts, job.last_error, job.locked_until, job.run_at = "pending", 0, None, None, clock.now()


def owned_application(session: Session, application_id: str, user_id: int) -> models.Application:
    application = session.get(models.Application, application_id)
    if application is None or application.owner_id != user_id:
        raise KeyError(application_id)
    return application


def application_summary(application: models.Application) -> dict:
    return {
        "id": application.id,
        "state": application.state,
        "business_type": application.business_type,
        "data_version": application.data_version,
        "payout_hold": application.payout_hold,
        "flags": list((application.flags or {}).keys()),
        "owner_id": application.owner_id,
        "anonymised": application.anonymised_at is not None,
        "created_at": application.created_at.isoformat(),
        "state_entered_at": application.state_entered_at.isoformat(),
        "age_seconds": int((clock.now() - application.created_at).total_seconds()),
    }


def _iso(timestamp, timespec: str = "seconds"):
    return timestamp.isoformat(timespec=timespec) if timestamp else None


def application_detail(session: Session, application: models.Application, unmask: bool = False) -> dict:
    form = load_form(session, application)

    fields = []
    extracted_rows = session.scalars(
        select(models.ExtractedField)
        .where(models.ExtractedField.application_id == application.id,
               models.ExtractedField.data_version == application.data_version)
        .order_by(models.ExtractedField.id)
    )
    for field_row in extracted_rows:
        fields.append({
            "doc_type": field_row.doc_type,
            "field": field_row.field_name,
            "value": decrypt_json(field_row.value_enc) if unmask else field_row.value_masked,
            "confidence": field_row.confidence,
            "source": field_row.source,
            "status": field_row.validation_status,
            "detail": field_row.detail,
        })

    checks = []
    verifications = session.scalars(
        select(models.Verification)
        .where(models.Verification.application_id == application.id)
        .order_by(models.Verification.id)
    )
    for verification in verifications:
        checks.append({
            "id": verification.id,
            "check": verification.check_type,
            "attempt": verification.attempt,
            "status": verification.status,
            "reason": verification.reason_code,
            "data_version": verification.data_version,
            "deadline_at": _iso(verification.deadline_at, "auto"),
            "result": safe_result(verification.result_json),
        })

    review_tasks = []
    tasks = session.scalars(
        select(models.ReviewTask)
        .where(models.ReviewTask.application_id == application.id)
        .order_by(models.ReviewTask.id)
    )
    for task in tasks:
        review_tasks.append({
            "id": task.id,
            "reason": task.reason_code,
            "status": task.status,
            "priority": task.priority,
            "resolution": task.resolution,
            "context": task.context,
            "opened_at": task.opened_at.isoformat(),
        })

    documents = []
    stored_documents = session.scalars(
        select(models.Document)
        .where(models.Document.application_id == application.id)
        .order_by(models.Document.id)
    )
    for document in stored_documents:
        documents.append({
            "id": document.id,
            "type": document.doc_type,
            "label": DOC_LABEL.get(document.doc_type, document.doc_type),
            "filename": document.filename,
            "content_type": document.content_type,
            "encrypted_file": bool(document.storage_path),
            "purged": document.purged_at is not None,
            "uploaded_at": document.uploaded_at.isoformat(timespec="seconds"),
            "data_version": document.data_version,
        })

    merchant = session.scalars(
        select(models.Merchant).where(models.Merchant.application_id == application.id)
    ).first()

    form_values = {}
    for field_name, value in form.items():
        if not field_name.startswith("_"):
            form_values[field_name] = value if unmask else mask_field(field_name, value)

    detail = application_summary(application)
    detail.update({
        "form": form_values,
        "missing_info": application.missing_info or [],
        "fields": fields,
        "checks": checks,
        "review_tasks": review_tasks,
        "documents": documents,
        "audit": audit_trail(session, application.id),
        "merchant_id": merchant.merchant_id if merchant else None,
        "flag_details": application.flags or {},
        "docs_purged_at": _iso(application.docs_purged_at),
        "anonymised_at": _iso(application.anonymised_at),
    })
    return detail


def audit_trail(session: Session, application_id: str) -> list[dict]:
    audit_events = session.scalars(
        select(models.AuditEvent)
        .where(models.AuditEvent.application_id == application_id)
        .order_by(models.AuditEvent.id)
    )
    return [
        {
            "id": audit_event.id,
            "ts": audit_event.ts.isoformat(timespec="seconds"),
            "actor": audit_event.actor,
            "event": audit_event.event_type,
            "from": audit_event.from_state,
            "to": audit_event.to_state,
            "payload": audit_event.payload,
        }
        for audit_event in audit_events
    ]


STAGES = ["Submitted", "Documents", "Verification", "Review", "Approved", "Live"]
STAGE_INDEX_BY_STATE = {states.SUBMITTED: 0, states.EXTRACTING: 1, states.NEEDS_INFO: 1, states.VERIFYING: 2,
                        states.MANUAL_REVIEW: 3, states.APPROVED: 4, states.PROVISIONING_FAILED: 4, states.ACTIVE: 5}
HEADLINES = {
    states.SUBMITTED: (
        "We received your application",
        "We'll start checking your documents in a moment.",
        "info",
    ),
    states.EXTRACTING: (
        "Checking your documents",
        "We're reading and validating the details in your documents.",
        "info",
    ),
    states.NEEDS_INFO: (
        "Action needed",
        "Please fix the items below and resubmit. Nothing else is needed from you.",
        "warn",
    ),
    states.VERIFYING: (
        "Verifying your details",
        "We're confirming your PAN, GST and bank details. This usually takes a few minutes.",
        "info",
    ),
    states.MANUAL_REVIEW: (
        "Under review by our team",
        "A specialist is looking at your application. We'll ask if we need anything.",
        "info",
    ),
    states.APPROVED: (
        "Approved",
        "We're setting up your merchant account.",
        "success",
    ),
    states.PROVISIONING_FAILED: (
        "Approved - finishing set-up",
        "There is a short technical delay setting up your account. Our team has been notified.",
        "info",
    ),
    states.ACTIVE: (
        "You're live",
        "Your merchant account is active and ready to accept payments.",
        "success",
    ),
    states.REJECTED: (
        "Application not approved",
        "We couldn't approve this application. You can start a new one at any time.",
        "danger",
    ),
    states.EXPIRED: (
        "Application expired",
        "We didn't hear back in time. You can start a new application at any time.",
        "muted",
    ),
    states.WITHDRAWN: (
        "Application withdrawn",
        "You withdrew this application. Its data is deleted according to our retention policy.",
        "muted",
    ),
}
_TIMELINE_TEXT_BY_EVENT = {
    "APPLICATION_SUBMITTED": "You submitted your application",
    "EXTRACTION_DONE": "Your documents were processed",
    "DATA_CHANGED": "You updated your details",
    "AWAITING_DOCUMENTS": "We're waiting for your documents",
    "DOCUMENTS_COMPLETE": "All your documents are in",
    "MERCHANT_ID_CREATED": "Your merchant account was created",
}
_TIMELINE_TEXT_BY_STATE = {
    states.VERIFYING: "Verification started", states.MANUAL_REVIEW: "Sent to our review team",
    states.APPROVED: "Application approved", states.ACTIVE: "Merchant account is live",
    states.REJECTED: "Application not approved", states.EXPIRED: "Application expired",
    states.WITHDRAWN: "You withdrew the application"}


def _document_status_for_merchant(document: models.Document | None, field_statuses: set[str],
                                  has_extraction_result: bool) -> tuple[str, str]:
    if document is None:
        return "Not provided", "danger"
    if "BLURRY" in field_statuses:
        return "Unclear: please upload a clearer copy", "warn"
    if "INVALID" in field_statuses or "MISSING" in field_statuses:
        return "Needs correction", "warn"
    if field_statuses & {"CONFLICT", "LOW_CONF"}:
        return "Being reviewed by our team", "info"
    if not has_extraction_result:
        return "Received", "info"
    return "Accepted", "success"


AWAITING_DOCUMENTS_HEADLINE = (
    "Waiting for your documents",
    "Upload the documents listed below. We start checking as soon as all of them are in.",
    "warn",
)


def headline_for(application: models.Application) -> tuple[str, str, str]:
    return AWAITING_DOCUMENTS_HEADLINE if is_awaiting_documents(application) else HEADLINES[application.state]


def merchant_view(session: Session, application: models.Application) -> dict:
    rules = load_rules()
    form = load_form(session, application)
    headline, message, tone = headline_for(application)
    required_doc_types = rules.required_documents(form.get("business_type", application.business_type))
    field_rows = session.scalars(select(models.ExtractedField).where(
        models.ExtractedField.application_id == application.id,
        models.ExtractedField.data_version == application.data_version)).all()
    latest_document_by_type = {document.doc_type: document for document in session.scalars(
        select(models.Document).where(models.Document.application_id == application.id).order_by(models.Document.id))}
    document_rows = []
    for doc_type in required_doc_types:
        document = latest_document_by_type.get(doc_type)
        field_statuses = {row.validation_status for row in field_rows if row.doc_type == doc_type}
        status_label, status_tone = _document_status_for_merchant(document, field_statuses, bool(field_rows))
        document_rows.append({
            "type": doc_type, "label": DOC_LABEL[doc_type], "id": document.id if document else None,
            "status": status_label, "tone": status_tone,
            "uploaded_at": document.uploaded_at.isoformat(timespec="minutes") if document else None,
            "purged": bool(document and document.purged_at),
            "has_file": bool(document and document.storage_path and not document.purged_at)})
    merchant = session.scalars(select(models.Merchant).where(models.Merchant.application_id == application.id)).first()
    timeline = []
    for audit_entry in audit_trail(session, application.id):
        if audit_entry["event"] == "NOTIFY_MERCHANT":
            messages = audit_entry["payload"].get("messages", [])
            if len(messages) == 1:
                text = messages[0]
            else:
                text = f"We asked you for {len(messages)} updates"
            timeline.append({"ts": audit_entry["ts"], "text": text})
        elif audit_entry["event"] in _TIMELINE_TEXT_BY_EVENT:
            timeline.append({"ts": audit_entry["ts"], "text": _TIMELINE_TEXT_BY_EVENT[audit_entry["event"]]})
        elif audit_entry["event"] == "STATE_CHANGE" and audit_entry["to"] in _TIMELINE_TEXT_BY_STATE:
            timeline.append({"ts": audit_entry["ts"], "text": _TIMELINE_TEXT_BY_STATE[audit_entry["to"]]})
    return {
        "id": application.id, "state": application.state, "headline": headline, "message": message, "tone": tone,
        "stage": STAGE_INDEX_BY_STATE.get(application.state), "stages": STAGES,
        "ended": application.state in states.TERMINAL,
        "needs_action": application.state == states.NEEDS_INFO or is_awaiting_documents(application),
        "missing_info": application.missing_info or [], "documents": document_rows,
        "timeline": list(reversed(timeline)), "merchant_id": merchant.merchant_id if merchant else None,
        "form": {field_name: value for field_name, value in form.items() if not field_name.startswith("_")},
        "business_type": application.business_type, "created_at": application.created_at.isoformat(timespec="minutes"),
        "anonymised": application.anonymised_at is not None, "docs_purged": application.docs_purged_at is not None,
        "can_withdraw": (application.state not in states.TERMINAL and application.state != states.ACTIVE
                         and merchant is None),
        "can_edit": application.state not in states.TERMINAL and application.anonymised_at is None}


def my_applications(session: Session, user_id: int) -> list[dict]:
    summaries = []
    for application in session.scalars(select(models.Application).where(models.Application.owner_id == user_id)
                                       .order_by(models.Application.created_at.desc())):
        form = load_form(session, application)
        headline, _message, tone = headline_for(application)
        summaries.append({"id": application.id, "state": application.state, "headline": headline, "tone": tone,
                          "name": form.get("legal_name") or "(removed)",
                          "created_at": application.created_at.isoformat(timespec="minutes"),
                          "needs_action": application.state == states.NEEDS_INFO or is_awaiting_documents(application)})
    return summaries
