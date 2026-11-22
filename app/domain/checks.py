from ..extraction.validators import normalize_identifier, pan_holder_name
from ..security import stable_hash

ENDPOINTS = {"PAN": "/pan/verify", "GST": "/gst/verify", "BANK": "/bank/verify", "RISK": "/risk/score"}


def check_inputs(check_type: str, form: dict) -> dict:
    if check_type == "PAN":
        return {
            "pan": normalize_identifier(form.get("pan")),
            "name": pan_holder_name(form),
        }

    if check_type == "GST":
        return {
            "gstin": normalize_identifier(form.get("gstin")),
            "pan": normalize_identifier(form.get("pan")),
        }

    if check_type == "BANK":
        return {
            "account": normalize_identifier(form.get("bank_account")),
            "ifsc": normalize_identifier(form.get("ifsc")),
            "holder": form.get("account_holder", ""),
        }

    if check_type == "RISK":
        return {
            "pan": normalize_identifier(form.get("pan")),
            "gstin": normalize_identifier(form.get("gstin")),
            "account": normalize_identifier(form.get("bank_account")),
            "ifsc": normalize_identifier(form.get("ifsc")),
            "business_type": form.get("business_type", ""),
            "pincode": form.get("pincode", ""),
        }

    raise ValueError(check_type)


def input_hash(check_type: str, form: dict) -> str:
    inputs = check_inputs(check_type, form)
    return stable_hash(check_type, *[f"{name}={value}" for name, value in sorted(inputs.items())])
