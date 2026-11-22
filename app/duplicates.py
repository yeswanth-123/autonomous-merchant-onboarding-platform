from rapidfuzz import fuzz
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .domain import states
from .domain.rules import Rules
from .extraction.validators import normalize_identifier
from .security import stable_hash

NOT_MATCHED_STATES = (states.WITHDRAWN, states.EXPIRED)


def identity_keys_for(form: dict) -> dict[str, str]:
    keys = {}
    if form.get("pan"):
        keys["PAN"] = stable_hash("PAN", normalize_identifier(form["pan"]))
    if form.get("gstin"):
        keys["GSTIN"] = stable_hash("GSTIN", normalize_identifier(form["gstin"]))
    if form.get("bank_account") and form.get("ifsc"):
        keys["ACCOUNT"] = stable_hash(
            "ACC",
            normalize_identifier(form["bank_account"]),
            normalize_identifier(form["ifsc"]),
        )
    return keys


def without_cleared_matches(duplicate_details: dict | None, cleared_duplicates: dict | None) -> dict | None:
    if not duplicate_details:
        return None
    remaining_candidates = [candidate for candidate in duplicate_details["candidates"]
                            if not set(candidate["matched_on"]) <= set((cleared_duplicates or {}).get(
                                candidate["application_id"], []))]
    return {**duplicate_details, "candidates": remaining_candidates} if remaining_candidates else None


def refresh_and_check(session: Session, application: models.Application, form: dict, rules: Rules) -> dict | None:
    own_keys = identity_keys_for(form)
    stored_key_rows = session.scalars(select(models.IdentityKey).where(
        models.IdentityKey.application_id == application.id)).all()
    current_key_pairs = set(own_keys.items())
    for stored_key in stored_key_rows:
        if (stored_key.kind, stored_key.key_hash) not in current_key_pairs:
            session.delete(stored_key)
    stored_key_pairs = {(stored_key.kind, stored_key.key_hash) for stored_key in stored_key_rows}
    for kind, key_hash in own_keys.items():
        if (kind, key_hash) not in stored_key_pairs:
            session.add(models.IdentityKey(application_id=application.id, kind=kind, key_hash=key_hash))
    session.flush()

    matched_kinds_by_application: dict[str, set] = {}
    for kind, key_hash in own_keys.items():
        for identity_key in session.scalars(
                select(models.IdentityKey).join(models.Application,
                                                models.Application.id == models.IdentityKey.application_id)
                .where(models.IdentityKey.key_hash == key_hash, models.IdentityKey.application_id != application.id,
                       models.Application.state.not_in(NOT_MATCHED_STATES))):
            matched_kinds_by_application.setdefault(identity_key.application_id, set()).add(kind)
    name_threshold = float(rules.get("duplicates.name_match", 92))
    if application.legal_name_norm and application.pincode:
        for other_application in session.scalars(select(models.Application).where(
                models.Application.id != application.id, models.Application.pincode == application.pincode,
                models.Application.state.not_in(NOT_MATCHED_STATES))):
            if (other_application.legal_name_norm and fuzz.token_set_ratio(
                    application.legal_name_norm, other_application.legal_name_norm) >= name_threshold):
                matched_kinds_by_application.setdefault(other_application.id, set()).add("NAME+PINCODE")
    if not matched_kinds_by_application:
        return None
    return {"candidates": [{"application_id": candidate_id, "matched_on": sorted(matched_kinds)}
                           for candidate_id, matched_kinds in matched_kinds_by_application.items()]}
