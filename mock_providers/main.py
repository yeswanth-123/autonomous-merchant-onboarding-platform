import asyncio
import json
import logging
import os
import uuid

import httpx
from fastapi import FastAPI, HTTPException, Request

from app.security import sign

logger = logging.getLogger("mock")
app = FastAPI(title="Mock verification providers")
WEBHOOK_SECRET = os.environ.get("ONB_WEBHOOK_SECRET", "dev-webhook-secret").encode()
DEFAULT_REPLY_SECONDS = float(os.environ.get("ONB_DEMO_STEP_SECONDS", "0") or 0) / 2 or 1.0

MOCK_STATE = {"default_scenarios": {}, "event_log": [], "responses_by_idempotency_key": {},
              "attempt_number_by_idempotency_key": {}, "attempt_counter_by_application_check": {},
              "outage_counter_by_application_check": {}, "merchant_id_by_idempotency_key": {},
              "merchant_calls_by_idempotency_key": {}}


def parse_scenario(scenario_text: str | None, attempt_number: int) -> dict:
    flags: dict = {}
    for token in (scenario_text or "").split(","):
        token = token.strip()
        if not token:
            continue
        attempt_limit = None
        if "@" in token:
            token, limit_text = token.rsplit("@", 1)
            attempt_limit = int(limit_text)
        if attempt_limit is not None and attempt_number > attempt_limit:
            continue
        name, _, argument = token.partition(":")
        flags[name] = argument or True
    return flags


def _record_event(kind: str, **details):
    MOCK_STATE["event_log"].append({"kind": kind, **details})
    del MOCK_STATE["event_log"][:-300]


async def _send_callback(callback_url: str, payload: dict):
    body = json.dumps(payload).encode()
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            response = await client.post(callback_url, content=body,
                                         headers={"X-Signature": sign(body, WEBHOOK_SECRET),
                                                  "Content-Type": "application/json"})
            _record_event("callback_sent", event_id=payload["event_id"],
                          status=payload["status"], http=response.status_code)
        except httpx.HTTPError as error:
            _record_event("callback_failed", error=str(error))


async def _deliver_result(provider: str, request_body: dict, flags: dict):
    delay_seconds = float(flags["delay"]) if isinstance(flags.get("delay"), str) else DEFAULT_REPLY_SECONDS
    if "never" in flags:
        _record_event("callback_suppressed", provider=provider, request_id=request_body["request_id"])
        return
    if "late" in flags:
        delay_seconds = float(request_body.get("timeout_seconds", 30)) + 3.0
    await asyncio.sleep(delay_seconds)
    submitted_data = request_body.get("data", {})
    if "fail" in flags:
        status = "FAILED"
        reason_code = flags["fail"] if isinstance(flags["fail"], str) else "UNKNOWN"
        result_data = {}
    else:
        status, reason_code = "VERIFIED", None
        risk_level = flags["risk"] if isinstance(flags.get("risk"), str) else "LOW"
        result_data = {
            "PAN": {"name_on_pan": submitted_data.get("name")},
            "GST": {"gstin": submitted_data.get("gstin")},
            "BANK": {"account_holder": submitted_data.get("holder"), "penny_drop": "SUCCESS"},
            "RISK": {"risk": risk_level, "score": 12},
        }[provider]

    callback_payload = {
        "event_id": "evt_" + uuid.uuid4().hex[:12],
        "provider": provider,
        "request_id": request_body["request_id"],
        "status": status,
        "reason_code": reason_code,
        "data": result_data,
    }
    await _send_callback(request_body["callback_url"], callback_payload)

    if "dup" in flags:
        await asyncio.sleep(0.3)
        await _send_callback(request_body["callback_url"], callback_payload)


async def _handle_verification_request(provider: str, request: Request):
    request_body = await request.json()
    idempotency_key = request.headers.get("Idempotency-Key") or request_body.get("idempotency_key")
    if idempotency_key in MOCK_STATE["responses_by_idempotency_key"]:
        return MOCK_STATE["responses_by_idempotency_key"][idempotency_key]
    application_check_key = ":".join(idempotency_key.split(":")[:2])
    if idempotency_key not in MOCK_STATE["attempt_number_by_idempotency_key"]:
        counters = MOCK_STATE["attempt_counter_by_application_check"]
        counters[application_check_key] = counters.get(application_check_key, 0) + 1
        MOCK_STATE["attempt_number_by_idempotency_key"][idempotency_key] = counters[application_check_key]
    attempt_number = MOCK_STATE["attempt_number_by_idempotency_key"][idempotency_key]
    scenario_text = request_body.get("scenario") or MOCK_STATE["default_scenarios"].get(provider)
    flags = parse_scenario(scenario_text, attempt_number)
    if "err" in flags:
        outage_limit = int(flags["err"]) if isinstance(flags["err"], str) else 1
        outage_counters = MOCK_STATE["outage_counter_by_application_check"]
        outage_counters[application_check_key] = outage_counters.get(application_check_key, 0) + 1
        if outage_counters[application_check_key] <= outage_limit:
            _record_event("submission_503", provider=provider, request_id=request_body["request_id"])
            raise HTTPException(503, "provider temporarily unavailable")
    response_body = {"request_id": request_body["request_id"], "status": "ACCEPTED"}
    MOCK_STATE["responses_by_idempotency_key"][idempotency_key] = response_body
    _record_event("accepted", provider=provider, request_id=request_body["request_id"], attempt=attempt_number,
                  scenario=flags)
    asyncio.create_task(_deliver_result(provider, request_body, flags))
    return response_body


@app.post("/pan/verify", status_code=202)
async def verify_pan(request: Request):
    return await _handle_verification_request("PAN", request)


@app.post("/gst/verify", status_code=202)
async def verify_gst(request: Request):
    return await _handle_verification_request("GST", request)


@app.post("/bank/verify", status_code=202)
async def verify_bank(request: Request):
    return await _handle_verification_request("BANK", request)


@app.post("/risk/score", status_code=202)
async def score_risk(request: Request):
    return await _handle_verification_request("RISK", request)


@app.post("/merchant-service/create", status_code=201)
async def create_merchant(request: Request):
    request_body = await request.json()
    idempotency_key = request.headers.get("Idempotency-Key") or request_body["application_id"]
    if idempotency_key in MOCK_STATE["merchant_id_by_idempotency_key"]:
        return {"merchant_id": MOCK_STATE["merchant_id_by_idempotency_key"][idempotency_key], "idempotent_replay": True}
    scenario_text = (request_body.get("scenario") or "").strip()
    call_counts = MOCK_STATE["merchant_calls_by_idempotency_key"]
    call_counts[idempotency_key] = call_counts.get(idempotency_key, 0) + 1
    call_number = call_counts[idempotency_key]
    fails_first_calls = scenario_text.startswith("fail:") and call_number <= int(scenario_text.split(":")[1])
    if scenario_text == "always_fail" or fails_first_calls:
        _record_event("merchant_503", idempotency_key=idempotency_key, call=call_number)
        raise HTTPException(503, "merchant service unavailable")
    merchant_id = "MID" + uuid.uuid4().hex[:10].upper()
    MOCK_STATE["merchant_id_by_idempotency_key"][idempotency_key] = merchant_id
    _record_event("merchant_created", idempotency_key=idempotency_key, merchant_id=merchant_id, call=call_number)
    return {"merchant_id": merchant_id}


@app.post("/mock/scenarios")
async def set_default_scenarios(request: Request):
    MOCK_STATE["default_scenarios"].update(await request.json())
    return MOCK_STATE["default_scenarios"]


@app.post("/mock/reset")
async def reset_mock():
    for state_value in MOCK_STATE.values():
        state_value.clear()
    return {"ok": True}


@app.get("/mock/log")
async def get_event_log():
    return MOCK_STATE["event_log"]


@app.get("/health")
async def health():
    return {"ok": True}
