from collections import defaultdict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import clock, models
from .domain import states

EXCEPTION_STATES = (states.NEEDS_INFO, states.MANUAL_REVIEW, states.PROVISIONING_FAILED)


def _percentile_95(values):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))]


def compute(session: Session) -> dict:
    now = clock.now()
    by_state = {state_name: 0 for state_name in states.ALL_STATES}
    for state_name, count in session.execute(select(models.Application.state, func.count())
                                             .group_by(models.Application.state)):
        by_state[state_name] = count
    total_applications = sum(by_state.values())

    state_changes_by_application = defaultdict(list)
    for state_change in session.scalars(select(models.AuditEvent).where(
            models.AuditEvent.event_type == "STATE_CHANGE").order_by(models.AuditEvent.id)):
        state_changes_by_application[state_change.application_id].append(state_change)
    seconds_in_state = defaultdict(list)
    applications_with_exceptions, seconds_to_active = set(), []
    for application_id, state_changes in state_changes_by_application.items():
        for index, state_change in enumerate(state_changes):
            if state_change.to_state in EXCEPTION_STATES:
                applications_with_exceptions.add(application_id)
            left_state_at = state_changes[index + 1].ts if index + 1 < len(state_changes) else None
            if left_state_at:
                seconds_in_state[state_change.to_state].append((left_state_at - state_change.ts).total_seconds())
            if state_change.to_state == states.ACTIVE:
                created_at = session.get(models.Application, application_id).created_at
                seconds_to_active.append((state_change.ts - created_at).total_seconds())
    time_in_state = {
        state_name: {"visits": len(durations), "avg_s": round(sum(durations) / len(durations), 2),
                     "p95_s": round(_percentile_95(durations), 2), "max_s": round(max(durations), 2)}
        for state_name, durations in seconds_in_state.items() if durations}

    callbacks_by_disposition = dict(session.execute(select(models.ProviderEvent.disposition, func.count())
                                                    .group_by(models.ProviderEvent.disposition)).all())
    duplicate_callbacks_ignored = session.scalar(select(func.count()).select_from(models.AuditEvent).where(
        models.AuditEvent.event_type == "CALLBACK_DUPLICATE_IGNORED")) or 0
    if total_applications:
        exception_rate = round(len(applications_with_exceptions) / total_applications, 3)
    else:
        exception_rate = 0.0

    if seconds_to_active:
        avg_time_to_active_s = round(sum(seconds_to_active) / len(seconds_to_active), 2)
    else:
        avg_time_to_active_s = None

    return {
        "total_applications": total_applications,
        "by_state": by_state,
        "exception_rate": exception_rate,
        "applications_with_exceptions": len(applications_with_exceptions),
        "time_in_state": time_in_state,
        "avg_time_to_active_s": avg_time_to_active_s,
        "open_review_tasks": session.scalar(select(func.count()).select_from(models.ReviewTask)
                                            .where(models.ReviewTask.status == "open")) or 0,
        "dead_jobs": session.scalar(select(func.count()).select_from(models.Job)
                                    .where(models.Job.status == "dead")) or 0,
        "callbacks_by_disposition": callbacks_by_disposition,
        "duplicate_callbacks_ignored": duplicate_callbacks_ignored,
        "generated_at": now.isoformat(timespec="seconds"),
    }
