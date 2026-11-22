import re

from rapidfuzz import fuzz

PAN_PATTERN = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")
GSTIN_PATTERN = re.compile(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$")
IFSC_PATTERN = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")
ACCOUNT_PATTERN = re.compile(r"^[0-9]{9,18}$")

PAN_HOLDER_TYPES = {"P": "individual", "C": "company", "F": "firm", "H": "huf", "A": "aop",
                    "T": "trust", "B": "boi", "L": "local", "J": "juridical", "G": "government"}
_GSTIN_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
SPECIAL_GSTIN_STATE_CODES = {97: "Other Territory", 99: "Centre Jurisdiction"}


def normalize_identifier(value) -> str:
    return re.sub(r"\s+", "", str(value or "")).upper()


def validate_pan(pan: str, business_type: str | None = None) -> tuple[bool, str]:
    pan = normalize_identifier(pan)
    if not PAN_PATTERN.match(pan):
        return False, "PAN must be 5 letters, 4 digits, then 1 letter"
    holder_type = PAN_HOLDER_TYPES.get(pan[3])
    if holder_type is None:
        return False, f"PAN 4th character '{pan[3]}' is not a valid holder type"
    if business_type in ("individual", "company", "firm", "trust") and holder_type != business_type:
        return False, f"PAN holder type '{holder_type}' does not match business type '{business_type}'"
    return True, ""


def gstin_checksum_char(first_14_characters: str) -> str:
    total = 0
    for position, character in enumerate(first_14_characters):
        weighted_value = _GSTIN_ALPHABET.index(character) * (1 if position % 2 == 0 else 2)
        total += weighted_value // 36 + weighted_value % 36
    return _GSTIN_ALPHABET[(36 - total % 36) % 36]


def validate_gstin(gstin: str, pan: str | None = None) -> tuple[bool, str]:
    gstin = normalize_identifier(gstin)
    if not GSTIN_PATTERN.match(gstin):
        return False, "GSTIN must be 15 characters in the standard format"
    state_code = int(gstin[:2])
    if not (1 <= state_code <= 38 or state_code in SPECIAL_GSTIN_STATE_CODES):
        return False, "GSTIN state code must be 01-38, 97 or 99"
    if gstin_checksum_char(gstin[:14]) != gstin[14]:
        return False, "GSTIN checksum digit is invalid"
    if pan and gstin[2:12] != normalize_identifier(pan):
        return False, "GSTIN does not contain the PAN provided"
    return True, ""


def validate_ifsc(ifsc: str) -> tuple[bool, str]:
    return (True, "") if IFSC_PATTERN.match(normalize_identifier(ifsc)) else (False, "IFSC must look like HDFC0001234")


def validate_account(account_number: str) -> tuple[bool, str]:
    return ((True, "") if ACCOUNT_PATTERN.match(normalize_identifier(account_number))
            else (False, "Account number must be 9-18 digits"))


_NAME_ABBREVIATIONS = {"PVT": "PRIVATE", "LTD": "LIMITED", "CO": "COMPANY", "&": "AND", "LLP": "LLP"}


def pan_holder_name(form: dict) -> str:
    if form.get("business_type") == "individual" and form.get("proprietor_name"):
        return form["proprietor_name"]
    return form.get("legal_name") or ""


def normalize_name(name: str) -> str:
    name = re.sub(r"[^\w&\s]", " ", str(name or "").upper())
    return " ".join(_NAME_ABBREVIATIONS.get(word, word) for word in name.split())


def name_score(first_name: str, second_name: str) -> float:
    return fuzz.token_set_ratio(normalize_name(first_name), normalize_name(second_name))
