import logging
import random
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select

from . import audit, clock, config, models
from .db import init_db, session_scope
from .domain import engine as workflow
from .domain import states
from .domain.checks import check_inputs, input_hash
from .domain.rules import load_rules
from .duplicates import refresh_and_check, without_cleared_matches
from .extraction.pipeline import load_form, persist_rows, run_extraction
from .providers import ProviderUnavailable, create_merchant, request_verification
from .security import redact_text

logger = logging.getLogger("worker")
LEASE_SECONDS = 60
LEASE_RENEWAL_SECONDS = 15


def _show_extracting_for_one_demo_step(job: models.Job):
    with session_scope() as session:
        application = session.get(models.Application, job.application_id)
        if job.payload.get("data_version") != application.data_version:
            return
        workflow.apply_event(session, application.id, {"type": "ExtractionStarted"}, "worker")
    time.sleep(config.DEMO_STEP_SECONDS)


def handle_extract_documents(job: models.Job):
    rules = load_rules()
    if config.DEMO_STEP_SECONDS and not job.payload.get("refresh_only"):
        _show_extracting_for_one_demo_step(job)
    with session_scope() as session:
        application = session.get(models.Application, job.application_id)
        if job.payload.get("data_version") != application.data_version:
            audit.record(session, application.id, "worker", "JOB_OBSOLETE", payload={"job": job.type})
            return
        is_refresh_only = bool(job.payload.get("refresh_only"))
        if not is_refresh_only:
            workflow.apply_event(session, application.id, {"type": "ExtractionStarted"}, "worker")
        extracted_rows = run_extraction(session, application, rules)
        persist_rows(session, application, extracted_rows)
        form = load_form(session, application)
        duplicate_details = without_cleared_matches(refresh_and_check(session, application, form, rules),
                                                    (application.flags or {}).get(workflow.CLEARED_DUPLICATES_FLAG))
        flags = dict(application.flags or {})
        if not is_refresh_only:
            flags.pop("duplicate_suspected", None)
            if duplicate_details:
                flags["duplicate_suspected"] = duplicate_details
        application.flags = flags
        problem_rows = [row for row in extracted_rows if row.status != "VALID"]
        audit.record(session, application.id, "worker", "EXTRACTION_DONE",
                     payload={"fields": len(extracted_rows),
                              "issues": [f"{row.doc_type}.{row.field_name}:{row.status}" for row in problem_rows],
                              "duplicate": bool(duplicate_details)})
        workflow.apply_event(session, application.id, {"type": "ExtractionDone"}, "worker")


@dataclass
class VerificationToSend:
    verification_id: int
    application_id: str
    check_type: str
    attempt: int
    request_id: str
    idempotency_key: str
    provider_data: dict
    scenario: str | None


def _prepare_verification_requests(job: models.Job, rules) -> list[VerificationToSend]:
    force = bool(job.payload.get("force"))
    pending_sends: list[VerificationToSend] = []
    with session_scope() as session:
        application = session.get(models.Application, job.application_id)
        if application.state != states.VERIFYING:
            audit.record(session, application.id, "worker", "JOB_OBSOLETE",
                         payload={"job": job.type, "state": application.state})
            return []
        form = load_form(session, application)
        for check_type in job.payload["checks"]:
            current_input_hash = input_hash(check_type, form)
            matching_rows = [row for row in session.scalars(select(models.Verification).where(
                models.Verification.application_id == application.id, models.Verification.check_type == check_type,
                models.Verification.input_hash == current_input_hash).order_by(models.Verification.id))
                if row.status != "SUPERSEDED"]
            latest = matching_rows[-1] if matching_rows else None
            verification = None
            if latest is None:
                attempt = 1
            elif latest.status in ("REQUESTED", "PENDING") and latest.sent_at is None:
                verification = latest
            elif latest.status == "TIMED_OUT" and (latest.attempt < rules.max_attempts or force):
                attempt = latest.attempt + 1
            elif latest.status in ("FAILED", "ERROR") and force:
                attempt = latest.attempt + 1
            else:
                continue
            if verification is None:
                verification = models.Verification(
                    application_id=application.id, check_type=check_type, attempt=attempt, status="REQUESTED",
                    request_id="req_" + uuid.uuid4().hex[:16],
                    idempotency_key=f"{application.id}:{check_type}:{current_input_hash[:12]}:{attempt}",
                    input_hash=current_input_hash, data_version=application.data_version)
                session.add(verification)
                session.flush()
            pending_sends.append(VerificationToSend(
                verification_id=verification.id, application_id=application.id, check_type=check_type,
                attempt=verification.attempt, request_id=verification.request_id,
                idempotency_key=verification.idempotency_key, provider_data=check_inputs(check_type, form),
                scenario=(application.scenarios or {}).get(check_type)))
    return pending_sends


def handle_start_verifications(job: models.Job):
    rules = load_rules()
    errors = []
    for pending_send in _prepare_verification_requests(job, rules):
        try:
            request_verification(pending_send.check_type, pending_send.request_id, pending_send.idempotency_key,
                                 pending_send.provider_data, pending_send.scenario, rules.timeout_seconds)
        except ProviderUnavailable as error:
            errors.append(str(error))
            with session_scope() as session:
                audit.record(session, pending_send.application_id, "worker", "PROVIDER_UNAVAILABLE",
                             payload={"check": pending_send.check_type, "error": str(error), "attempt": job.attempts})
            continue
        _record_request_sent(pending_send, rules.timeout_seconds)
    if errors:
        raise ProviderUnavailable("; ".join(errors))


def _record_request_sent(pending_send: VerificationToSend, timeout_seconds: float):
    with session_scope() as session:
        verification = session.get(models.Verification, pending_send.verification_id)
        now = clock.now()
        if verification.sent_at is None:
            verification.sent_at = now
        if verification.status == "REQUESTED":
            verification.status = "PENDING"
            verification.deadline_at = now + timedelta(seconds=timeout_seconds)
        audit.record(session, pending_send.application_id, "worker", "VERIFICATION_REQUESTED",
                     payload={"check": pending_send.check_type, "attempt": pending_send.attempt,
                              "request_id": pending_send.request_id,
                              "deadline": (verification.deadline_at or now).isoformat(timespec="seconds")})


def on_dead_start_verifications(job: models.Job, error_text: str):
    with session_scope() as session:
        unsent_verifications = session.scalars(select(models.Verification).where(
            models.Verification.application_id == job.application_id, models.Verification.sent_at.is_(None),
            models.Verification.status == "REQUESTED")).all()
        for verification in unsent_verifications:
            verification.status, verification.reason_code = "ERROR", "PROVIDER_UNAVAILABLE"
        workflow.apply_event(session, job.application_id,
                             {"type": "VerificationUpdate", "detail": "provider outage exhausted"}, "worker")


def handle_create_merchant(job: models.Job):
    with session_scope() as session:
        application = session.get(models.Application, job.application_id)
        if application.state != states.APPROVED:
            audit.record(session, application.id, "worker", "JOB_OBSOLETE",
                         payload={"job": job.type, "state": application.state})
            return
        existing_merchant = session.scalars(select(models.Merchant).where(
            models.Merchant.application_id == application.id)).first()
        if existing_merchant:
            workflow.apply_event(session, application.id,
                                 {"type": "MerchantCreated", "merchant_id": existing_merchant.merchant_id}, "worker")
            return
        scenario = (application.scenarios or {}).get("MERCHANT")
        form = load_form(session, application)
        profile = {"legal_name": form.get("legal_name"), "business_type": application.business_type}
        application_id = application.id
    merchant_id = create_merchant(application_id, f"merchant:{application_id}", scenario, profile)
    with session_scope() as session:
        application = session.get(models.Application, application_id)
        if application.state != states.APPROVED:
            audit.record(session, application_id, "worker", "MERCHANT_ID_DISCARDED_STALE_APPROVAL",
                         payload={"merchant_id": merchant_id, "state": application.state})
            return
        if not session.scalars(select(models.Merchant).where(models.Merchant.application_id == application_id)).first():
            session.add(models.Merchant(merchant_id=merchant_id, application_id=application_id,
                                        config={"payments": "enabled"}))
        audit.record(session, application_id, "worker", "MERCHANT_ID_CREATED", payload={"merchant_id": merchant_id})
        workflow.apply_event(session, application_id, {"type": "MerchantCreated", "merchant_id": merchant_id}, "worker")


def on_dead_extract_documents(job: models.Job, error_text: str):
    with session_scope() as session:
        application = session.get(models.Application, job.application_id)
        if application is None or job.payload.get("data_version") != application.data_version:
            return
        workflow.apply_event(session, application.id, {"type": "ExtractionFailed", "error": error_text}, "worker")


def on_dead_create_merchant(job: models.Job, error_text: str):
    with session_scope() as session:
        workflow.apply_event(session, job.application_id,
                             {"type": "MerchantCreationFailed", "error": error_text}, "worker")


JOB_HANDLERS = {"EXTRACT_DOCUMENTS": handle_extract_documents, "START_VERIFICATIONS": handle_start_verifications,
                "CREATE_MERCHANT": handle_create_merchant}
DEAD_LETTER_HANDLERS = {"EXTRACT_DOCUMENTS": on_dead_extract_documents,
                        "START_VERIFICATIONS": on_dead_start_verifications, "CREATE_MERCHANT": on_dead_create_merchant}


def backoff_seconds(job_type: str, attempts: int) -> float:
    rules = load_rules()
    if job_type == "CREATE_MERCHANT":
        base_seconds, cap_seconds = float(rules.get("provisioning.backoff_base_seconds", 2)), 60.0
    else:
        base_seconds = float(rules.get("job_defaults.backoff_base_seconds", 2))
        cap_seconds = float(rules.get("job_defaults.backoff_cap_seconds", 60))
    return min(base_seconds * 2 ** (attempts - 1), cap_seconds) * random.uniform(0.9, 1.1)


def lease_jobs(limit: int = 10) -> list[int]:
    with session_scope() as session:
        now = clock.now()
        due_jobs = session.scalars(select(models.Job).where(
            ((models.Job.status == "pending") & (models.Job.run_at <= now)) |
            ((models.Job.status == "leased") & (models.Job.locked_until < now))
        ).order_by(models.Job.run_at).limit(limit)).all()
        for job in due_jobs:
            job.status, job.locked_until = "leased", now + timedelta(seconds=LEASE_SECONDS)
            job.attempts += 1
        return [job.id for job in due_jobs]


def renew_lease(job_id: int) -> bool:
    with session_scope() as session:
        job = session.get(models.Job, job_id)
        if job is None or job.status != "leased":
            return False
        job.locked_until = clock.now() + timedelta(seconds=LEASE_SECONDS)
        return True


class LeaseKeeper:
    def __init__(self, job_id: int):
        self.job_id = job_id
        self.stop_requested = threading.Event()
        self.renewal_thread = threading.Thread(target=self._renew_until_stopped, name=f"lease-{job_id}", daemon=True)

    def _renew_until_stopped(self):
        while not self.stop_requested.wait(LEASE_RENEWAL_SECONDS):
            try:
                if not renew_lease(self.job_id):
                    return
            except Exception:
                logger.warning("could not renew the lease of job %s", self.job_id, exc_info=True)

    def __enter__(self):
        self.renewal_thread.start()
        return self

    def __exit__(self, *_exception_info):
        self.stop_requested.set()
        self.renewal_thread.join()


def run_job(job_id: int):
    with session_scope() as session:
        job = session.get(models.Job, job_id)
        session.expunge(job)
    handler = JOB_HANDLERS.get(job.type)
    try:
        if handler is None:
            raise RuntimeError(f"no handler for {job.type}")
        with LeaseKeeper(job_id):
            handler(job)
        with session_scope() as session:
            session.get(models.Job, job_id).status = "done"
    except Exception as error:
        error_text = redact_text(f"{type(error).__name__}: {error}")
        logger.warning("job %s (%s) failed attempt %s: %s", job_id, job.type, job.attempts, error_text)
        is_dead = job.attempts >= job.max_attempts
        with session_scope() as session:
            job_record = session.get(models.Job, job_id)
            job_record.last_error = error_text
            if is_dead:
                job_record.status = "dead"
                audit.record(session, job_record.application_id, "worker", "JOB_DEAD_LETTERED",
                             payload={"job_id": job_id, "type": job_record.type, "error": error_text,
                                      "attempts": job_record.attempts})
            else:
                retry_delay = backoff_seconds(job_record.type, job_record.attempts)
                job_record.status, job_record.locked_until = "pending", None
                job_record.run_at = clock.now() + timedelta(seconds=retry_delay)
                audit.record(session, job_record.application_id, "worker", "JOB_RETRY_SCHEDULED",
                             payload={"job_id": job_id, "type": job_record.type, "attempt": job_record.attempts,
                                      "retry_in_s": round(retry_delay, 1), "error": error_text})
        if is_dead and job.type in DEAD_LETTER_HANDLERS:
            DEAD_LETTER_HANDLERS[job.type](job, error_text)


def run_due_jobs() -> int:
    processed_count = 0
    while True:
        job_ids = lease_jobs()
        if not job_ids:
            return processed_count
        for job_id in job_ids:
            run_job(job_id)
            processed_count += 1


def sweep() -> dict:
    rules = load_rules()
    now = clock.now()
    report = {"timed_out": 0, "expired": 0}
    with session_scope() as session:
        overdue_verifications = session.scalars(select(models.Verification).where(
            models.Verification.status.in_(("REQUESTED", "PENDING")), models.Verification.sent_at.is_not(None),
            models.Verification.deadline_at < now)).all()
        for verification in overdue_verifications:
            verification.status, verification.completed_at = "TIMED_OUT", now
            audit.record(session, verification.application_id, "system", "VERIFICATION_TIMED_OUT",
                         payload={"check": verification.check_type, "attempt": verification.attempt,
                                  "request_id": verification.request_id})
            timeout_event = {"type": "VerificationUpdate", "detail": f"{verification.check_type} timed out"}
            workflow.apply_event(session, verification.application_id, timeout_event, "system")
            report["timed_out"] += 1
        expiry_cutoff = now - timedelta(seconds=rules.expiry_seconds)
        for application in session.scalars(select(models.Application).where(
                models.Application.state.in_((states.NEEDS_INFO, states.SUBMITTED)),
                models.Application.state_entered_at < expiry_cutoff)).all():
            if application.state == states.SUBMITTED and "awaiting_documents" not in (application.flags or {}):
                continue
            workflow.apply_event(session, application.id, {"type": "Expire"}, "system")
            report["expired"] += 1
    return report


def run_forever(poll_seconds: float = 0.5, sweep_every_seconds: float = 2.0):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    init_db()
    logger.info("worker started")
    last_sweep_at = last_retention_at = 0.0
    retention_every_seconds = float(load_rules().get("retention.sweep_interval_seconds", 3600))
    while True:
        try:
            run_due_jobs()
            if time.monotonic() - last_sweep_at >= sweep_every_seconds:
                sweep()
                last_sweep_at = time.monotonic()
            if time.monotonic() - last_retention_at >= retention_every_seconds:
                from .retention import run_retention
                with session_scope() as session:
                    run_retention(session, actor="system")
                last_retention_at = time.monotonic()
        except Exception:
            logger.exception("worker loop error")
        time.sleep(poll_seconds)


if __name__ == "__main__":
    run_forever()
