from sqlalchemy.orm import Session

from . import models
from .security import redact


def record(session: Session, application_id: str | None, actor: str, event_type: str,
           from_state: str | None = None, to_state: str | None = None, payload: dict | None = None):
    audit_event = models.AuditEvent(application_id=application_id, actor=actor, event_type=event_type,
                                    from_state=from_state, to_state=to_state, payload=redact(payload or {}))
    session.add(audit_event)
    return audit_event
