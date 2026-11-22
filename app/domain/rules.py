import os
from functools import lru_cache

import yaml

from .. import config


class Rules:
    def __init__(self, data: dict):
        self.data = data

    def get(self, dotted_path: str, default=None):
        current = self.data
        for part in dotted_path.split("."):
            if not isinstance(current, dict) or part not in current:
                return default
            current = current[part]
        return current

    @property
    def business_types(self) -> list[str]:
        return list(self.data.get("business_types") or ["company", "firm", "trust", "individual"])

    def required_checks(self, business_type: str) -> list[str]:
        checks_by_business_type = self.data["required_checks"]
        return list(checks_by_business_type.get(business_type, checks_by_business_type["default"]))

    def required_documents(self, business_type: str) -> list[str]:
        documents_by_business_type = self.data["required_documents"]
        return list(documents_by_business_type.get(business_type, documents_by_business_type["default"]))

    @property
    def timeout_seconds(self) -> float:
        return float(os.environ.get("ONB_TIMEOUT_SECONDS", self.data["verification"]["timeout_seconds"]))

    @property
    def max_attempts(self) -> int:
        return int(self.data["verification"]["max_attempts"])

    @property
    def expiry_seconds(self) -> float:
        return float(os.environ.get("ONB_EXPIRY_SECONDS", self.data["needs_info_expiry_seconds"]))

    def reason_action(self, reason_code: str | None) -> str:
        actions = self.data["reason_actions"]
        return actions.get(reason_code or "", actions["DEFAULT"])

    def message(self, reason_code: str | None) -> str:
        return self.data.get("messages", {}).get(reason_code or "",
                                                 f"Verification failed ({reason_code}). Please review your details.")


@lru_cache(maxsize=1)
def load_rules() -> Rules:
    with open(config.RULES_FILE) as rules_file:
        return Rules(yaml.safe_load(rules_file))
