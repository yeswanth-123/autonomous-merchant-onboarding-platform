from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, event, func, select
from sqlalchemy.orm import Session

from . import audit, auth, clock, config, models
from .domain import states
from .domain.rules import load_rules
from .security import encrypt_json


FILES_TO_DELETE_KEY = "retention_files_to_delete"
DELETION_HOOKS_KEY = "retention_deletion_hooks_installed"


def _policy_value(key: str, default):
    return load_rules().get(f"retention.{key}", default)


def _delete_files_after_commit(session: Session, file_paths: list[Path]):
    session.info.setdefault(FILES_TO_DELETE_KEY, []).extend(file_paths)
    if not session.info.get(DELETION_HOOKS_KEY):
        event.listen(session, "after_commit", _delete_scheduled_files)
        event.listen(session, "after_rollback", _forget_scheduled_files)
        session.info[DELETION_HOOKS_KEY] = True


def _delete_scheduled_files(session: Session):
    for file_path in session.info.pop(FILES_TO_DELETE_KEY, []):
        file_path.unlink(missing_ok=True)
        application_folder = file_path.parent
        if application_folder.exists() and not any(application_folder.iterdir()):
            application_folder.rmdir()


def _forget_scheduled_files(session: Session):
    session.info.pop(FILES_TO_DELETE_KEY, None)


def purge_documents(session: Session, application: models.Application, actor: str, reason: str) -> int:
    now = clock.now()
    removed_count = 0
    files_to_delete = []
    for document in session.scalars(select(models.Document).where(
            models.Document.application_id == application.id, models.Document.purged_at.is_(None))):
        if document.storage_path:
            files_to_delete.append(Path(document.storage_path))
        document.storage_path, document.payload_enc, document.purged_at = None, None, now
        removed_count += 1
    for field_row in session.scalars(select(models.ExtractedField).where(
            models.ExtractedField.application_id == application.id)):
        field_row.value_enc = field_row.value_masked = None
    application_folder = config.UPLOAD_DIR / application.id
    if application_folder.exists():
        files_to_delete.extend(path for path in application_folder.iterdir() if path not in files_to_delete)
    _delete_files_after_commit(session, files_to_delete)
    application.docs_purged_at = now
    audit.record(session, application.id, actor, "RETENTION_DOCUMENTS_PURGED",
                 payload={"documents": removed_count, "reason": reason})
    return removed_count


def anonymise_application(session: Session, application: models.Application, actor: str, reason: str):
    if application.state not in states.TERMINAL:
        raise ValueError(f"only an ended application can be anonymised (state is {application.state})")
    if application.docs_purged_at is None:
        purge_documents(session, application, actor, reason)
    for version_row in session.scalars(select(models.ApplicationVersion).where(
            models.ApplicationVersion.application_id == application.id)):
        version_row.form_data_enc, version_row.form_hash = encrypt_json({"_anonymised": True}), ""
    session.execute(delete(models.IdentityKey).where(models.IdentityKey.application_id == application.id))
    for verification in session.scalars(select(models.Verification).where(
            models.Verification.application_id == application.id)):
        verification.result_json, verification.input_hash = None, "anonymised"
    application.legal_name_norm, application.pincode = "", ""
    application.scenarios, application.missing_info, application.flags = {}, [], {}
    application.anonymised_at = clock.now()
    audit.record(session, application.id, actor, "RETENTION_ANONYMISED", payload={"reason": reason})


def retention_days_for(session: Session, application: models.Application) -> tuple[int, int]:
    if session.scalar(select(func.count()).select_from(models.Merchant)
                      .where(models.Merchant.application_id == application.id)):
        merchant_days = int(_policy_value("merchant_retention_days", 2555))
        return merchant_days, merchant_days
    return int(_policy_value("terminal_documents_days", 30)), int(_policy_value("terminal_anonymise_days", 90))


def _is_due(session: Session, application: models.Application, now) -> tuple[bool, bool]:
    documents_days, anonymise_days = retention_days_for(session, application)
    time_since_ended = now - application.state_entered_at
    return (application.docs_purged_at is None and time_since_ended >= timedelta(days=documents_days),
            application.anonymised_at is None and time_since_ended >= timedelta(days=anonymise_days))


def run_retention(session: Session, actor: str = "system", now=None) -> dict:
    now = now or clock.now()
    raw_payload_days = int(_policy_value("provider_raw_payload_days", 30))
    report = {"documents_purged": 0, "anonymised": 0, "raw_payloads_cleared": 0, "sessions_removed": 0}

    ended_applications = session.scalars(select(models.Application).where(
        models.Application.state.in_(tuple(states.TERMINAL)))).all()
    for application in ended_applications:
        documents_due, anonymise_due = _is_due(session, application, now)
        documents_days, anonymise_days = retention_days_for(session, application)
        if documents_due:
            purge_documents(session, application, actor, f"{application.state} for {documents_days}+ days")
            report["documents_purged"] += 1
        if anonymise_due:
            anonymise_application(session, application, actor, f"{application.state} for {anonymise_days}+ days")
            report["anonymised"] += 1

    clear_result = session.execute(models.ProviderEvent.__table__.update().where(
        models.ProviderEvent.received_at <= now - timedelta(days=raw_payload_days),
        models.ProviderEvent.raw_enc != "").values(raw_enc=""))
    report["raw_payloads_cleared"] = clear_result.rowcount or 0
    report["sessions_removed"] = auth.purge_expired_sessions(session)
    audit.record(session, None, actor, "RETENTION_RUN", payload=report)
    return report
