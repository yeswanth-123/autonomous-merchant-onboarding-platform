from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, clock, config, models
from ..extraction.pipeline import load_form
from . import states
from .checks import input_hash
from .evaluate import (CheckView, Decision, FieldIssue, Snapshot, checks_needing_request, evaluate_checks,
                       evaluate_extraction)
from .rules import Rules, load_rules

BANK_FIELD_NAMES = {"bank_account", "ifsc", "account_holder"}
ACTIVE_VERIFICATION_JOB_STATUSES = ("pending", "leased")
REVIEWER_ACCEPTED_FLAG = "reviewer_accepted"
CLEARED_DUPLICATES_FLAG = "reviewer_cleared_duplicates"
UNANSWERED_CHECK_STATUSES = ("ERROR", "TIMED_OUT")


class ConflictError(Exception):
    pass


DEMO_PACED_JOBS = ("EXTRACT_DOCUMENTS", "CREATE_MERCHANT")


def enqueue(session: Session, job_type: str, application_id: str | None, payload: dict | None = None,
            delay_seconds: float = 0, idempotency_key: str | None = None, max_attempts: int | None = None):
    if idempotency_key and session.scalars(select(models.Job).where(
            models.Job.idempotency_key == idempotency_key)).first():
        return None
    rules = load_rules()
    if job_type in DEMO_PACED_JOBS and not (payload or {}).get("refresh_only"):
        delay_seconds = max(delay_seconds, config.DEMO_STEP_SECONDS)
    job = models.Job(type=job_type, application_id=application_id, payload=payload or {},
                     run_at=clock.now() + timedelta(seconds=delay_seconds), idempotency_key=idempotency_key,
                     max_attempts=max_attempts or int(rules.get("job_defaults.max_attempts", 5)))
    session.add(job)
    return job


def open_review(session: Session, application: models.Application, reason: str, context: dict | None = None,
                priority: int = 2):
    task = models.ReviewTask(
        application_id=application.id,
        reason_code=reason,
        priority=priority,
        context=context or {},
    )
    session.add(task)
    audit.record(session, application.id, "system", "REVIEW_TASK_OPENED",
                 payload={"reason": reason, "context": context or {}})
    return task


def close_review_tasks(session: Session, application_id: str, resolution: str, actor: str, notes: str | None = None):
    for task in session.scalars(select(models.ReviewTask).where(models.ReviewTask.application_id == application_id,
                                                                models.ReviewTask.status == "open")):
        task.status, task.resolution, task.resolved_at = "resolved", resolution, clock.now()
        task.assignee, task.notes = actor, notes


def merchant_of(session: Session, application_id: str) -> models.Merchant | None:
    return session.scalars(select(models.Merchant).where(models.Merchant.application_id == application_id)).first()


def disable_merchant_payments(session: Session, application: models.Application, actor: str, reason: str):
    merchant = merchant_of(session, application.id)
    if merchant is None or (merchant.config or {}).get("payments") == "disabled":
        return
    merchant.config = {**(merchant.config or {}), "payments": "disabled"}
    audit.record(session, application.id, actor, "MERCHANT_PAYMENTS_DISABLED",
                 payload={"merchant_id": merchant.merchant_id, "reason": reason})


def is_under_payout_review(session: Session, application: models.Application) -> bool:
    return application.state == states.MANUAL_REVIEW and (
        application.payout_hold or merchant_of(session, application.id) is not None)


def transition(session: Session, application: models.Application, target_state: str, actor: str,
               reasons: list[str] | None = None, extra: dict | None = None):
    previous_state = application.state
    states.assert_legal(previous_state, target_state)
    application.state = target_state
    application.version += 1
    application.state_entered_at = application.updated_at = clock.now()
    audit.record(session, application.id, actor, "STATE_CHANGE", previous_state, target_state,
                 {"reasons": reasons or [], **(extra or {})})
    if previous_state in (states.MANUAL_REVIEW, states.PROVISIONING_FAILED) and target_state != previous_state:
        close_review_tasks(session, application.id, "auto_closed", actor)
    if previous_state == states.NEEDS_INFO:
        application.missing_info = []
    if target_state in states.TERMINAL:
        disable_merchant_payments(session, application, actor, f"application {target_state}")


def build_snapshot(session: Session, application: models.Application, rules: Rules) -> Snapshot:
    form = load_form(session, application)
    required_checks = rules.required_checks(form.get("business_type", application.business_type))
    verification_rows = session.scalars(select(models.Verification).where(
        models.Verification.application_id == application.id).order_by(models.Verification.id)).all()
    check_views: dict[str, CheckView | None] = {}
    for check_type in required_checks:
        current_input_hash = input_hash(check_type, form)
        matching_rows = [row for row in verification_rows
                         if row.check_type == check_type and row.input_hash == current_input_hash
                         and row.status != "SUPERSEDED"]
        if matching_rows:
            latest = matching_rows[-1]
            check_views[check_type] = CheckView(latest.status, latest.attempt, latest.reason_code, latest.result_json,
                                                latest.sent_at is not None)
        else:
            check_views[check_type] = None
    accepted_results = (application.flags or {}).get(REVIEWER_ACCEPTED_FLAG) or {}
    accepted_checks = {check_type for check_type, accepted in accepted_results.items()
                       if check_type in required_checks and accepted.get("input_hash") == input_hash(check_type, form)}
    issues = [FieldIssue(field_row.validation_status, field_row.detail, field_row.doc_type, field_row.field_name)
              for field_row in session.scalars(select(models.ExtractedField).where(
                  models.ExtractedField.application_id == application.id,
                  models.ExtractedField.data_version == application.data_version))
              if field_row.validation_status != "VALID"]
    return Snapshot(application.state, required_checks, check_views, dict(application.flags or {}), issues,
                    accepted_checks)


def _apply(session: Session, application: models.Application, decision: Decision, actor: str, rules: Rules,
           force: bool = False):
    if decision.next_state != application.state:
        transition(session, application, decision.next_state, actor, decision.reasons)
        if decision.next_state == states.NEEDS_INFO:
            application.missing_info = decision.missing_info
            audit.record(session, application.id, "system", "NOTIFY_MERCHANT",
                         payload={"messages": decision.missing_info})
        elif decision.next_state == states.MANUAL_REVIEW:
            open_review(session, application, decision.review_reason or "REVIEW", decision.review_context)
        elif decision.next_state == states.APPROVED:
            enqueue(session, "CREATE_MERCHANT", application.id,
                    idempotency_key=f"create_merchant:{application.id}:v{application.version}",
                    max_attempts=int(rules.get("provisioning.max_attempts", 4)))
        elif decision.next_state == states.REJECTED:
            audit.record(session, application.id, "system", "NOTIFY_MERCHANT",
                         payload={"messages": ["Application rejected: " + "; ".join(decision.reasons)]})
    if decision.next_state == states.VERIFYING and decision.request_checks:
        already_queued_checks = checks_in_queued_verification_jobs(session, application.id)
        checks_to_request = [check_type for check_type in decision.request_checks
                             if check_type not in already_queued_checks]
        if not checks_to_request:
            return
        latest_request_rows = dict(session.execute(
            select(models.Verification.check_type, func.max(models.Verification.id))
            .where(models.Verification.application_id == application.id)
            .group_by(models.Verification.check_type)).all())
        attempt_labels = ",".join(f"{check_type}#{latest_request_rows.get(check_type, 0)}"
                                  for check_type in checks_to_request)
        enqueue(session, "START_VERIFICATIONS", application.id, {"checks": checks_to_request, "force": force},
                idempotency_key=f"start:{application.id}:v{application.version}:{attempt_labels}:{int(force)}")


def checks_in_queued_verification_jobs(session: Session, application_id: str) -> set[str]:
    queued_checks: set[str] = set()
    for job in session.scalars(select(models.Job).where(
            models.Job.application_id == application_id, models.Job.type == "START_VERIFICATIONS",
            models.Job.status.in_(ACTIVE_VERIFICATION_JOB_STATUSES))):
        queued_checks.update((job.payload or {}).get("checks", []))
    return queued_checks


def _evaluate_checks_now(session: Session, application: models.Application, rules: Rules, actor: str,
                         force: bool = False):
    decision = evaluate_checks(build_snapshot(session, application, rules), rules)
    _apply(session, application, decision, actor, rules, force)


def apply_event(session: Session, application_id: str, event: dict, actor: str = "system") -> models.Application:
    rules = load_rules()
    application = session.get(models.Application, application_id)
    if application is None:
        raise KeyError(application_id)
    event_type = event["type"]

    if event_type == "ExtractionStarted":
        if application.state == states.SUBMITTED:
            transition(session, application, states.EXTRACTING, actor)

    elif event_type == "ExtractionDone":
        if application.state != states.EXTRACTING:
            audit.record(session, application.id, actor, "EVENT_IGNORED",
                         payload={"event": event_type, "state": application.state})
            return application
        decision = evaluate_extraction(build_snapshot(session, application, rules), rules)
        _apply(session, application, decision, actor, rules)
        if application.state == states.VERIFYING:
            _evaluate_checks_now(session, application, rules, actor)

    elif event_type == "VerificationUpdate":
        if application.state == states.VERIFYING:
            snapshot = build_snapshot(session, application, rules)
            _apply(session, application, evaluate_checks(snapshot, rules), actor, rules)
        else:
            audit.record(session, application.id, actor, "EVENT_NO_STATE_CHANGE",
                         payload={"event": event.get("detail"), "state": application.state})

    elif event_type == "DataChanged":
        _on_data_changed(session, application, event, actor)

    elif event_type == "OperatorAction":
        _on_operator_action(session, application, event, actor, rules)

    elif event_type == "LateContradiction":
        _on_late_contradiction(session, application, event, actor)

    elif event_type == "MerchantCreated":
        if application.state == states.APPROVED:
            transition(session, application, states.ACTIVE, actor, extra={"merchant_id": event["merchant_id"]})
            late_result = (application.flags or {}).get("late_callback")
            late_result_contradicts_approval = bool(late_result) and late_result.get("late_status") != "VERIFIED"
            application.payout_hold = late_result_contradicts_approval
            application.flags = {name: detail for name, detail in (application.flags or {}).items()
                                 if name != "post_activation_change"
                                 and (name != "late_callback" or late_result_contradicts_approval)}
            if late_result_contradicts_approval:
                _on_late_contradiction(session, application, {"type": "LateContradiction", **late_result}, actor)

    elif event_type == "ExtractionFailed":
        if application.state in (states.SUBMITTED, states.EXTRACTING):
            transition(session, application, states.MANUAL_REVIEW, actor, ["document processing failed repeatedly"])
            open_review(session, application, "EXTRACTION_FAILED", {"error": event.get("error", "")}, priority=1)
        else:
            audit.record(session, application.id, actor, "EVENT_IGNORED",
                         payload={"event": event_type, "state": application.state})

    elif event_type == "MerchantCreationFailed":
        if application.state == states.APPROVED:
            transition(session, application, states.PROVISIONING_FAILED, actor, [event.get("error", "")])
            open_review(session, application, "PROVISIONING_FAILED", {"error": event.get("error")}, priority=1)

    elif event_type == "Withdraw":
        if application.state == states.ACTIVE:
            raise ConflictError("an active merchant account cannot be withdrawn; contact support")
        if application.state in states.TERMINAL:
            raise ConflictError(f"application is already {application.state}")
        if merchant_of(session, application.id) is not None:
            raise ConflictError(
                "this merchant account has already been activated and cannot be withdrawn; contact support"
            )
        transition(session, application, states.WITHDRAWN, actor, ["withdrawn by merchant"])
        close_review_tasks(session, application.id, "withdrawn", actor)
        application.missing_info = []

    elif event_type == "Expire":
        waiting_for_documents = application.state == states.SUBMITTED and "awaiting_documents" in (application.flags or {})
        if application.state == states.NEEDS_INFO or waiting_for_documents:
            transition(session, application, states.EXPIRED, actor, ["no merchant response before deadline"])
            audit.record(session, application.id, "system", "NOTIFY_MERCHANT",
                         payload={"messages": ["Application expired."]})
    else:
        raise ValueError(f"unknown event {event_type}")
    return application


def _on_late_contradiction(session: Session, application: models.Application, event: dict, actor: str):
    contradiction = {"check": event["check"], "late_status": event["late_status"],
                     "reason_code": event.get("reason_code"), "request_id": event.get("request_id")}
    application.payout_hold = True
    application.flags = {**(application.flags or {}), "late_callback": contradiction}
    if application.state == states.ACTIVE:
        transition(session, application, states.MANUAL_REVIEW, actor,
                   [f"late {contradiction['check']} callback contradicts the approval"])
        open_review(session, application, "LATE_FAILURE_AFTER_APPROVAL",
                    {**contradiction, "payout_hold": True}, priority=1)
    else:
        audit.record(session, application.id, actor, "LATE_FAILURE_DEFERRED",
                     payload={**contradiction, "note": "escalates when merchant creation completes"})


def _on_data_changed(session: Session, application: models.Application, event: dict, actor: str):
    if application.state in states.TERMINAL:
        raise ConflictError(f"application is {application.state}; submit a new application")
    changed_fields = set(event.get("changed_fields", []))
    audit.record(session, application.id, actor, "DATA_CHANGED",
                 payload={"data_version": application.data_version, "changed_fields": sorted(changed_fields)})
    if application.state == states.ACTIVE:
        if changed_fields & BANK_FIELD_NAMES:
            application.payout_hold = True
        application.flags = {**(application.flags or {}),
                             "post_activation_change": {"changed_fields": sorted(changed_fields)}}
        transition(session, application, states.MANUAL_REVIEW, actor, ["merchant data changed after activation"])
        open_review(session, application, "POST_ACTIVATION_CHANGE",
                    {"changed_fields": sorted(changed_fields), "payout_hold": application.payout_hold}, priority=1)
        _enqueue_refresh_extraction(session, application)
        return
    if is_under_payout_review(session, application):
        if changed_fields & BANK_FIELD_NAMES:
            application.payout_hold = True
        flags = dict(application.flags or {})
        if "post_activation_change" in flags:
            previously_changed_fields = set(flags["post_activation_change"].get("changed_fields", []))
            flags["post_activation_change"] = {"changed_fields": sorted(previously_changed_fields | changed_fields)}
        application.flags = flags
        audit.record(session, application.id, actor, "REVIEW_DATA_UPDATED",
                     payload={"changed_fields": sorted(changed_fields), "payout_hold": application.payout_hold,
                              "note": "the review stays open; a reviewer decides"})
        _enqueue_refresh_extraction(session, application)
        return
    if application.state not in (states.SUBMITTED, states.EXTRACTING):
        application.flags = flags_kept_on_data_change(application.flags)
        transition(session, application, states.EXTRACTING, actor, ["merchant data changed"])
    enqueue(session, "EXTRACT_DOCUMENTS", application.id, {"data_version": application.data_version},
            idempotency_key=f"extract:{application.id}:{application.data_version}")


def flags_kept_on_data_change(flags: dict | None) -> dict:
    kept_flags = {}
    late_result = (flags or {}).get("late_callback")
    if late_result and late_result.get("late_status") != "VERIFIED":
        kept_flags["late_callback"] = late_result
    for decision_flag in (REVIEWER_ACCEPTED_FLAG, CLEARED_DUPLICATES_FLAG):
        if (flags or {}).get(decision_flag):
            kept_flags[decision_flag] = flags[decision_flag]
    return kept_flags


def _enqueue_refresh_extraction(session: Session, application: models.Application):
    enqueue(session, "EXTRACT_DOCUMENTS", application.id,
            {"data_version": application.data_version, "refresh_only": True},
            idempotency_key=f"extract:{application.id}:{application.data_version}:refresh")


def _approve_after_review(session: Session, application: models.Application, open_tasks: list[models.ReviewTask],
                          actor: str, reason: str, rules: Rules):
    snapshot = build_snapshot(session, application, rules)
    form = load_form(session, application)
    accepted_results = dict((application.flags or {}).get(REVIEWER_ACCEPTED_FLAG) or {})
    for task in open_tasks:
        reviewed_check = ("RISK" if task.reason_code == "HIGH_RISK"
                          else (task.context or {}).get("check") if task.reason_code.startswith("CHECK_FAILED_")
                          else None)
        check_view = snapshot.checks.get(reviewed_check) if reviewed_check else None
        if check_view is None or check_view.status in UNANSWERED_CHECK_STATUSES:
            continue
        accepted_results[reviewed_check] = {"input_hash": input_hash(reviewed_check, form), "status": check_view.status,
                                            "reason_code": check_view.reason_code}
        audit.record(session, application.id, actor, "CHECK_RESULT_ACCEPTED_BY_REVIEWER",
                     payload={"check": reviewed_check, "status": check_view.status,
                              "reason_code": check_view.reason_code, "reason": reason})
    if accepted_results:
        application.flags = {**(application.flags or {}), REVIEWER_ACCEPTED_FLAG: accepted_results}
    cleared_duplicates = dict((application.flags or {}).get(CLEARED_DUPLICATES_FLAG) or {})
    for task in open_tasks:
        if task.reason_code == "DUPLICATE_SUSPECTED":
            for candidate in (task.context or {}).get("candidates", []):
                candidate_id = candidate["application_id"]
                previously_cleared = set(cleared_duplicates.get(candidate_id, []))
                cleared_duplicates[candidate_id] = sorted(previously_cleared | set(candidate["matched_on"]))
    if cleared_duplicates:
        application.flags = {**(application.flags or {}), CLEARED_DUPLICATES_FLAG: cleared_duplicates}

    transition(session, application, states.VERIFYING, actor, [reason, "approved by reviewer; verifying"])
    snapshot = build_snapshot(session, application, rules)
    unanswered_checks = [check_type for check_type in snapshot.required_checks
                         if check_type not in snapshot.accepted_checks and snapshot.checks.get(check_type)
                         and snapshot.checks[check_type].status in UNANSWERED_CHECK_STATUSES]
    checks_to_request = list(dict.fromkeys(checks_needing_request(snapshot, rules) + unanswered_checks))
    if checks_to_request:
        _apply(session, application, Decision(states.VERIFYING, request_checks=checks_to_request), actor, rules,
               force=True)
    else:
        _evaluate_checks_now(session, application, rules, actor)
    if application.state == states.APPROVED:
        application.payout_hold = False


def _on_operator_action(session: Session, application: models.Application, event: dict, actor: str, rules: Rules):
    action, reason = event["action"], (event.get("reason") or "").strip()
    if not reason:
        raise ValueError("a reason is mandatory for operator actions")
    audit.record(session, application.id, actor, "OPERATOR_ACTION", payload={"action": action, "reason": reason})
    current_state = application.state
    provisioning_attempts = int(rules.get("provisioning.max_attempts", 4))
    if current_state == states.PROVISIONING_FAILED:
        if action == "retry_provisioning":
            transition(session, application, states.APPROVED, actor, [reason])
            enqueue(session, "CREATE_MERCHANT", application.id,
                    idempotency_key=f"create_merchant:{application.id}:v{application.version}",
                    max_attempts=provisioning_attempts)
            return
        if action == "reject":
            close_review_tasks(session, application.id, action, actor, reason)
            transition(session, application, states.REJECTED, actor, [reason])
            audit.record(session, application.id, "system", "NOTIFY_MERCHANT",
                         payload={"messages": ["Application rejected: " + reason]})
            return
        raise ConflictError(f"action '{action}' is not valid in PROVISIONING_FAILED (use retry_provisioning or reject)")
    if action == "retry_provisioning":
        raise ConflictError("retry_provisioning only valid in PROVISIONING_FAILED")
    if current_state != states.MANUAL_REVIEW:
        raise ConflictError(f"action '{action}' requires MANUAL_REVIEW (state is {current_state})")
    open_tasks = session.scalars(select(models.ReviewTask).where(models.ReviewTask.application_id == application.id,
                                                                 models.ReviewTask.status == "open")).all()
    previous_flags = application.flags or {}
    close_review_tasks(session, application.id, action, actor, reason)
    kept_decisions = {CLEARED_DUPLICATES_FLAG: previous_flags.get(CLEARED_DUPLICATES_FLAG)}
    if action != "reverify":
        kept_decisions[REVIEWER_ACCEPTED_FLAG] = previous_flags.get(REVIEWER_ACCEPTED_FLAG)
    application.flags = {name: value for name, value in kept_decisions.items() if value}
    if action == "approve":
        _approve_after_review(session, application, open_tasks, actor, reason, rules)
    elif action == "reject":
        transition(session, application, states.REJECTED, actor, [reason])
    elif action == "request_info":
        message_to_merchant = event.get("message") or reason
        transition(session, application, states.NEEDS_INFO, actor, [reason])
        application.missing_info = [message_to_merchant]
        audit.record(session, application.id, "system", "NOTIFY_MERCHANT", payload={"messages": [message_to_merchant]})
    elif action == "retry_extraction":
        transition(session, application, states.EXTRACTING, actor, [reason])
        enqueue(session, "EXTRACT_DOCUMENTS", application.id, {"data_version": application.data_version},
                idempotency_key=f"extract:{application.id}:{application.data_version}:retry:v{application.version}")
    elif action == "reverify":
        transition(session, application, states.VERIFYING, actor, [reason])
        snapshot = build_snapshot(session, application, rules)
        checks_to_request = checks_needing_request(snapshot, rules, force=True)
        if checks_to_request:
            enqueue(session, "START_VERIFICATIONS", application.id, {"checks": checks_to_request, "force": True},
                    idempotency_key=f"start:{application.id}:v{application.version}:{','.join(checks_to_request)}:1")
        else:
            _evaluate_checks_now(session, application, rules, actor)
    else:
        raise ValueError(f"unknown action {action}")
