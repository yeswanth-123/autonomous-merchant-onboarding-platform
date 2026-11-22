import json

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import audit, clock, models
from .domain import engine as workflow
from .domain import states
from .domain.checks import input_hash
from .domain.rules import load_rules
from .extraction.pipeline import load_form
from .security import encrypt_json, verify_signature
from .services import safe_result


class BadSignature(Exception):
    pass


class MalformedCallback(Exception):
    pass


ALREADY_APPROVED_STATES = (states.APPROVED, states.PROVISIONING_FAILED, states.ACTIVE)


def _parse_callback(raw_body: bytes) -> dict:
    try:
        body = json.loads(raw_body)
    except (ValueError, UnicodeDecodeError) as error:
        raise MalformedCallback("body is not valid JSON") from error
    if not isinstance(body, dict):
        raise MalformedCallback("body must be a JSON object")
    event_id = body.get("event_id")
    if not isinstance(event_id, str) or not event_id.strip() or len(event_id) > 64:
        raise MalformedCallback("event_id is missing or invalid")
    request_id = body.get("request_id")
    if request_id is not None and (not isinstance(request_id, str) or len(request_id) > 40):
        raise MalformedCallback("request_id is invalid")
    if body.get("data") is not None and not isinstance(body["data"], dict):
        raise MalformedCallback("data must be a JSON object")
    return body


def handle_webhook(session: Session, provider: str, raw_body: bytes, signature: str | None) -> dict:
    provider = provider.upper()
    provider_actor = f"provider:{provider}"
    rules = load_rules()
    if not verify_signature(raw_body, signature):
        audit.record(session, None, provider_actor, "CALLBACK_BAD_SIGNATURE")
        raise BadSignature()
    try:
        body = _parse_callback(raw_body)
    except MalformedCallback as error:
        audit.record(session, None, provider_actor, "CALLBACK_MALFORMED", payload={"error": str(error)})
        raise
    event_id, request_id = body["event_id"], body.get("request_id")

    provider_event = models.ProviderEvent(provider=provider, event_id=event_id, request_id=request_id,
                                          raw_enc=encrypt_json(body))
    savepoint = session.begin_nested()
    try:
        session.add(provider_event)
        session.flush()
        savepoint.commit()
    except IntegrityError:
        savepoint.rollback()
        verification = session.scalars(select(models.Verification).where(
            models.Verification.request_id == request_id)).first()
        audit.record(session, verification.application_id if verification else None, provider_actor,
                     "CALLBACK_DUPLICATE_IGNORED", payload={"event_id": event_id, "request_id": request_id})
        return {"status": "duplicate"}

    verification = session.scalars(select(models.Verification).where(
        models.Verification.request_id == request_id)).first()
    if verification is None or verification.check_type != provider:
        provider_event.disposition = "UNKNOWN"
        audit.record(session, None, provider_actor, "CALLBACK_UNKNOWN_REQUEST", payload={"request_id": request_id})
        return {"status": "unknown_request"}

    application = session.get(models.Application, verification.application_id)
    result = {"status": body.get("status"), "reason_code": body.get("reason_code"),
              "data": safe_result(body.get("data"))}

    if verification.input_hash != input_hash(verification.check_type, load_form(session, application)):
        provider_event.disposition = "STALE"
        audit.record(session, application.id, provider_actor, "CALLBACK_STALE_IGNORED",
                     payload={"check": verification.check_type, "request_id": request_id, "result": result})
        return {"status": "stale"}

    if verification.status in ("TIMED_OUT", "SUPERSEDED"):
        provider_event.disposition = "LATE"
        verification.result_json = {**(verification.result_json or {}), "late_result": result}
        audit.record(session, application.id, provider_actor, "CALLBACK_LATE",
                     payload={"check": verification.check_type, "request_id": request_id, "result": result})
        if application.state in ALREADY_APPROVED_STATES:
            if result["status"] == "VERIFIED":
                return {"status": "late_recorded"}
            workflow.apply_event(session, application.id,
                                 {"type": "LateContradiction", "check": verification.check_type,
                                  "late_status": result["status"], "reason_code": result.get("reason_code"),
                                  "request_id": request_id}, provider_actor)
            return {"status": "late_escalated"}
        if rules.get("late_callback_policy", "review") == "accept":
            _store_result(verification, result)
            workflow.apply_event(session, application.id,
                                 {"type": "VerificationUpdate", "detail": "late callback accepted"}, provider_actor)
            return {"status": "late_accepted"}
        application.flags = {**(application.flags or {}),
                             "late_callback": {"check": verification.check_type, "late_status": result["status"],
                                               "request_id": request_id}}
        workflow.apply_event(session, application.id, {"type": "VerificationUpdate", "detail": "late callback"},
                             provider_actor)
        return {"status": "late_quarantined"}

    if verification.status in ("VERIFIED", "FAILED"):
        provider_event.disposition = "DUPLICATE"
        audit.record(session, application.id, provider_actor, "CALLBACK_DUPLICATE_IGNORED",
                     payload={"event_id": event_id, "note": "request already completed"})
        return {"status": "duplicate"}

    _store_result(verification, result)
    audit.record(session, application.id, provider_actor, "CHECK_RESULT",
                 payload={"check": verification.check_type, "status": verification.status,
                          "reason": verification.reason_code, "attempt": verification.attempt,
                          "request_id": request_id})
    workflow.apply_event(session, application.id,
                         {"type": "VerificationUpdate", "detail": f"{verification.check_type} {verification.status}"},
                         provider_actor)
    return {"status": "applied"}


def _store_result(verification: models.Verification, result: dict):
    is_success = str(result.get("status", "")).upper() in ("VERIFIED", "SUCCESS", "OK")
    verification.status = "VERIFIED" if is_success else "FAILED"
    verification.reason_code = None if is_success else (result.get("reason_code") or "UNKNOWN")
    verification.result_json = {**(verification.result_json or {}), **(result.get("data") or {})}
    verification.completed_at = clock.now()
