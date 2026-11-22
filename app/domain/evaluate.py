from dataclasses import dataclass, field
from typing import NamedTuple

from . import states
from .rules import Rules

RISK_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
BLOCKING_FLAGS = ("late_callback", "duplicate_suspected", "post_activation_change", "other")
MERCHANT_FIXABLE_STATUSES = {"MISSING", "INVALID", "BLURRY"}
NEEDS_JUDGEMENT_STATUSES = {"LOW_CONF", "CONFLICT"}


class FieldIssue(NamedTuple):
    status: str
    detail: str
    doc_type: str
    field_name: str


@dataclass
class CheckView:
    status: str
    attempt: int = 1
    reason_code: str | None = None
    result: dict | None = None
    sent: bool = True


@dataclass
class Snapshot:
    state: str
    required_checks: list[str]
    checks: dict[str, CheckView | None]
    flags: dict = field(default_factory=dict)
    field_issues: list[FieldIssue] = field(default_factory=list)
    accepted_checks: set[str] = field(default_factory=set)

    def check_passed(self, check_type: str) -> bool:
        check_view = self.checks.get(check_type)
        return check_type in self.accepted_checks or bool(check_view and check_view.status == "VERIFIED")


@dataclass
class Decision:
    next_state: str
    reasons: list[str] = field(default_factory=list)
    missing_info: list[str] = field(default_factory=list)
    review_reason: str | None = None
    review_context: dict = field(default_factory=dict)
    request_checks: list[str] = field(default_factory=list)
    force: bool = False


def checks_needing_request(snapshot: Snapshot, rules: Rules, force: bool = False) -> list[str]:
    to_request = []
    identity_checks_passed = all(snapshot.check_passed(check_type)
                                 for check_type in snapshot.required_checks if check_type != "RISK")
    for check_type in snapshot.required_checks:
        check_view = snapshot.checks.get(check_type)
        if check_type in snapshot.accepted_checks:
            continue
        if check_type == "RISK" and not identity_checks_passed:
            continue
        if check_view is None:
            to_request.append(check_type)
        elif check_view.status in ("REQUESTED", "PENDING"):
            if not check_view.sent:
                to_request.append(check_type)
        elif check_view.status == "TIMED_OUT":
            if check_view.attempt < rules.max_attempts or force:
                to_request.append(check_type)
        elif check_view.status in ("FAILED", "ERROR") and force:
            to_request.append(check_type)
    return to_request


def evaluate_extraction(snapshot: Snapshot, rules: Rules) -> Decision:
    fixable_issues = [issue for issue in snapshot.field_issues if issue.status in MERCHANT_FIXABLE_STATUSES]
    if fixable_issues:
        return Decision(states.NEEDS_INFO,
                        reasons=[f"{issue.doc_type}.{issue.field_name}:{issue.status}" for issue in fixable_issues],
                        missing_info=[issue.detail for issue in fixable_issues])
    judgement_issues = [issue for issue in snapshot.field_issues if issue.status in NEEDS_JUDGEMENT_STATUSES]
    if judgement_issues:
        review_reason = ("DOCUMENT_CONFLICT" if any(issue.status == "CONFLICT" for issue in judgement_issues)
                         else "LOW_CONFIDENCE")
        return Decision(states.MANUAL_REVIEW, reasons=[issue.detail for issue in judgement_issues],
                        review_reason=review_reason,
                        review_context={"issues": [issue.detail for issue in judgement_issues]})
    if "duplicate_suspected" in snapshot.flags:
        duplicate_details = snapshot.flags["duplicate_suspected"]
        return Decision(states.MANUAL_REVIEW, reasons=["duplicate suspected"], review_reason="DUPLICATE_SUSPECTED",
                        review_context=duplicate_details if isinstance(duplicate_details, dict) else {})
    return Decision(states.VERIFYING, request_checks=checks_needing_request(snapshot, rules))


def evaluate_checks(snapshot: Snapshot, rules: Rules) -> Decision:
    check_views = {check_type: snapshot.checks.get(check_type) for check_type in snapshot.required_checks
                   if check_type not in snapshot.accepted_checks}

    for check_type, check_view in check_views.items():
        if check_view and check_view.status == "FAILED" and rules.reason_action(check_view.reason_code) == "reject":
            return Decision(states.REJECTED, reasons=[f"{check_type}:{check_view.reason_code}"])

    for flag_name in BLOCKING_FLAGS:
        if flag_name in snapshot.flags:
            return Decision(states.MANUAL_REVIEW, reasons=[flag_name], review_reason=flag_name.upper(),
                            review_context={"flag": snapshot.flags[flag_name]})

    failed = {check_type: view for check_type, view in check_views.items() if view and view.status == "FAILED"}
    needing_human = {check_type: view for check_type, view in failed.items()
                     if rules.reason_action(view.reason_code) == "manual_review"}
    if needing_human:
        check_type, check_view = next(iter(needing_human.items()))
        return Decision(states.MANUAL_REVIEW, reasons=[f"{check_type}:{check_view.reason_code}"],
                        review_reason=f"CHECK_FAILED_{check_view.reason_code}",
                        review_context={"check": check_type, "reason": check_view.reason_code})
    if failed:
        return Decision(states.NEEDS_INFO,
                        reasons=[f"{check_type}:{view.reason_code}" for check_type, view in failed.items()],
                        missing_info=[rules.message(view.reason_code) for view in failed.values()])

    for check_type, check_view in check_views.items():
        if check_view and check_view.status == "ERROR":
            return Decision(
                states.MANUAL_REVIEW,
                reasons=[f"{check_type}:provider error"],
                review_reason="PROVIDER_ERROR",
                review_context={"check": check_type, "reason": check_view.reason_code},
            )
        if check_view and check_view.status == "TIMED_OUT" and check_view.attempt >= rules.max_attempts:
            return Decision(
                states.MANUAL_REVIEW,
                reasons=[f"{check_type}:timed out"],
                review_reason="VERIFICATION_TIMEOUT",
                review_context={"check": check_type, "attempts": check_view.attempt},
            )

    risk_view = check_views.get("RISK")
    if risk_view and risk_view.status == "VERIFIED":
        risk_level = (risk_view.result or {}).get("risk", "LOW")
        if RISK_RANK.get(risk_level, 3) > RISK_RANK[rules.get("risk.auto_approve_max", "MEDIUM")]:
            return Decision(states.MANUAL_REVIEW, reasons=[f"risk {risk_level}"], review_reason="HIGH_RISK",
                            review_context={"risk": risk_level})

    if all(snapshot.check_passed(check_type) for check_type in snapshot.required_checks):
        return Decision(states.APPROVED, reasons=["all required checks verified"])

    return Decision(states.VERIFYING, request_checks=checks_needing_request(snapshot, rules))
