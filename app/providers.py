import time

import httpx

from . import config
from .domain.checks import ENDPOINTS


class ProviderUnavailable(Exception):
    pass


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, cooldown_seconds: float = 30.0):
        self.failure_threshold, self.cooldown_seconds = failure_threshold, cooldown_seconds
        self.consecutive_failures: dict[str, int] = {}
        self.opened_at: dict[str, float] = {}

    def allows_requests(self, provider_name: str) -> bool:
        opened_at = self.opened_at.get(provider_name)
        if opened_at is None:
            return True
        if time.monotonic() - opened_at <= self.cooldown_seconds:
            return False
        self.opened_at[provider_name] = time.monotonic()
        return True

    def record_success(self, provider_name: str):
        self.consecutive_failures[provider_name] = 0
        self.opened_at.pop(provider_name, None)

    def record_failure(self, provider_name: str):
        self.consecutive_failures[provider_name] = self.consecutive_failures.get(provider_name, 0) + 1
        if self.consecutive_failures[provider_name] >= self.failure_threshold:
            self.opened_at[provider_name] = time.monotonic()


breaker = CircuitBreaker()
_http_client: httpx.Client | None = None


def _client() -> httpx.Client:
    global _http_client
    if _http_client is None:
        _http_client = httpx.Client(base_url=config.MOCK_URL, timeout=httpx.Timeout(10.0, connect=3.0))
    return _http_client


def request_verification(check_type: str, request_id: str, idempotency_key: str, data: dict, scenario: str | None,
                         timeout_seconds: float) -> None:
    if not breaker.allows_requests(check_type):
        raise ProviderUnavailable(f"circuit open for {check_type}")
    request_body = {"request_id": request_id, "idempotency_key": idempotency_key, "data": data,
                    "callback_url": f"{config.API_URL}/webhooks/{check_type.lower()}", "scenario": scenario or "",
                    "timeout_seconds": timeout_seconds}
    try:
        response = _client().post(
            ENDPOINTS[check_type],
            json=request_body,
            headers={"Idempotency-Key": idempotency_key},
        )
    except httpx.HTTPError as error:
        breaker.record_failure(check_type)
        raise ProviderUnavailable(f"{check_type}: {error}") from error
    if response.status_code >= 500:
        breaker.record_failure(check_type)
        raise ProviderUnavailable(f"{check_type}: HTTP {response.status_code}")
    if response.status_code >= 400:
        raise ValueError(f"{check_type} rejected request: HTTP {response.status_code} {response.text[:200]}")
    breaker.record_success(check_type)


def create_merchant(application_id: str, idempotency_key: str, scenario: str | None, profile: dict) -> str:
    try:
        response = _client().post(
            "/merchant-service/create",
            json={"application_id": application_id, "scenario": scenario or "", "profile": profile},
            headers={"Idempotency-Key": idempotency_key},
        )
    except httpx.HTTPError as error:
        raise ProviderUnavailable(f"merchant-service: {error}") from error
    if response.status_code >= 400:
        raise ProviderUnavailable(f"merchant-service HTTP {response.status_code}")
    return response.json()["merchant_id"]
