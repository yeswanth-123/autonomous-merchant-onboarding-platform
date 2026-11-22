import io
import logging
import re
import shutil
from dataclasses import dataclass

from PIL import Image, ImageOps
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import filecrypt, models
from ..domain.rules import Rules
from ..security import decrypt_json, encrypt_json, mask_field
from . import validators
from .quality import quality_score

logger = logging.getLogger("extraction")
Image.MAX_IMAGE_PIXELS = 40_000_000

PHOTO_MIN_LONG_SIDE = 800
PHOTO_RECOMMENDED_LONG_SIDE = (1500, 4000)
MAX_SKEW_DEGREES = 15
ORIENTATION_SEARCH_LONG_SIDE = 2000
RIGHT_ANGLE_TURNS = (90, 180, 270)

DOC_FIELDS = {"PAN": ["pan", "name"], "GST": ["gstin", "gst_legal_name"],
              "BANK_PROOF": ["bank_account", "ifsc", "account_holder"]}
DOC_LABEL = {"PAN": "PAN card", "GST": "GST certificate", "BANK_PROOF": "cancelled cheque / bank proof"}
FORM_REQUIRED_FIELDS = ["legal_name", "business_type", "pan", "bank_account", "ifsc", "account_holder"]
IDENTIFIER_FIELDS = ("pan", "gstin", "ifsc", "bank_account")


@dataclass
class ExtractedRow:
    doc_type: str
    field_name: str
    value: str | None = None
    confidence: float | None = None
    source: str = "form"
    status: str = "VALID"
    detail: str = ""
    document_id: int | None = None


@dataclass
class ParsedDocument:
    fields: dict[str, str]
    confidence: float
    source: str
    quality: float | None = None
    note: str = ""
    unreadable: bool = False


def tesseract_available() -> bool:
    return shutil.which("tesseract") is not None


NAME_LABEL_ONLY_LINE = re.compile(r"(?<![\w'’])Name\s*:?(?:\s+[^A-Za-z\s]*(?:[A-Za-z][^A-Za-z\s]*){0,2})?\s*$", re.I)
OTHER_PERSON_LABEL = re.compile(r"Father|Mother|Spouse", re.I)
LABEL_WORDS = re.compile(r"\b(Name|Date|Birth|Signature|Incorporation|Formation|Permanent Account)\b", re.I)
ACCOUNT_NUMBER = re.compile(r"\b(?:Account|A\s*[/|lI1]?\s*[cCeo])\.?\s*(?:No|Number)\.?\s*[:.\-|]*\s*([0-9][0-9 ]{7,22}[0-9])", re.I)
CHEQUE_SIGNING_LINE = re.compile(r"^\s*For\s+([A-Z][A-Z0-9.&'\- ]{2,}?)\s*$", re.M)
PLEASE_SIGN_ABOVE = re.compile(r"Please\s+sign\s+above", re.I)


def _looks_like_a_name(line: str) -> bool:
    words = line.split()
    return (bool(words) and not LABEL_WORDS.search(line)
            and sum(bool(re.fullmatch(r"[A-Za-z][A-Za-z.&']*", word)) for word in words) >= max(1, len(words) - 1))


def _value_below_label(lines: list[str], label_index: int) -> str | None:
    for candidate in lines[label_index + 1:label_index + 3]:
        if candidate.strip():
            return candidate.strip() if _looks_like_a_name(candidate) else None
    return None


def parse_text(doc_type: str, text: str) -> dict[str, str]:
    text = text or ""
    lines = text.splitlines()
    fields: dict[str, str] = {}
    if doc_type == "PAN":
        if (match := re.search(r"(?<![<\w])[A-Z]{5}[0-9]{4}[A-Z](?![>\w])", text)):
            fields["pan"] = match.group()
        same_line_name = r"^[ \t]*Name\b(?![ \t]+of\b)[ \t]*[:\-]?[ \t]*(\S.*)$"
        if (match := re.search(same_line_name, text, re.I | re.M)):
            fields["name"] = match.group(1).strip()
        else:
            for index, line in enumerate(lines):
                if NAME_LABEL_ONLY_LINE.search(line) and not OTHER_PERSON_LABEL.search(line):
                    if (name := _value_below_label(lines, index)):
                        fields["name"] = name
                    break
    elif doc_type == "GST":
        if (match := re.search(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b", text)):
            fields["gstin"] = match.group()
        if (match := re.search(r"Legal Name[ \t]*[:\-]?[ \t]*(.+)", text, re.I)):
            fields["gst_legal_name"] = match.group(1).strip()
    elif doc_type == "BANK_PROOF":
        if (match := ACCOUNT_NUMBER.search(text)):
            digits = match.group(1).replace(" ", "")
            if 9 <= len(digits) <= 18:
                fields["bank_account"] = digits
        if (match := re.search(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", text)):
            fields["ifsc"] = match.group()
        if (match := re.search(r"Account Holder[ \t]*[:\-]?[ \t]*(.+)", text, re.I)):
            fields["account_holder"] = match.group(1).strip()
        elif (match := CHEQUE_SIGNING_LINE.search(text)):
            fields["account_holder"] = match.group(1).strip()
        else:
            for index, line in enumerate(lines):
                if PLEASE_SIGN_ABOVE.search(line):
                    previous_lines = [candidate for candidate in lines[max(0, index - 2):index] if candidate.strip()]
                    if previous_lines and _looks_like_a_name(previous_lines[-1]):
                        fields["account_holder"] = previous_lines[-1].strip()
                    break
    return fields


OCR_MIN_LONG_SIDE = 1500


SPARSE_TEXT_MODE = "--psm 11"


def _ocr_once(image: Image.Image, doc_type: str, tesseract_config: str = "") -> tuple[dict[str, str], float]:
    import pytesseract
    ocr_result = pytesseract.image_to_data(image, config=tesseract_config, output_type=pytesseract.Output.DICT)
    word_confidences, words_by_line, line_boxes = [], {}, {}
    for index, word in enumerate(ocr_result["text"]):
        if not word.strip():
            continue
        if float(ocr_result["conf"][index]) >= 0:
            word_confidences.append(float(ocr_result["conf"][index]))
        line_key = (ocr_result["block_num"][index], ocr_result["par_num"][index], ocr_result["line_num"][index])
        words_by_line.setdefault(line_key, []).append(word)
        left, top = ocr_result["left"][index], ocr_result["top"][index]
        right, bottom = left + ocr_result["width"][index], top + ocr_result["height"][index]
        known_box = line_boxes.get(line_key, (left, top, right, bottom))
        line_boxes[line_key] = (min(known_box[0], left), min(known_box[1], top),
                                max(known_box[2], right), max(known_box[3], bottom))
    recognised_text = "\n".join(" ".join(line_words) for line_words in words_by_line.values())
    fields = parse_text(doc_type, recognised_text)
    if len(fields) < len(DOC_FIELDS[doc_type]):
        row_fields = parse_text(doc_type, _text_by_visual_rows(words_by_line, line_boxes))
        fields = {**row_fields, **fields}
    return fields, _field_confidence(fields, ocr_result, word_confidences)


def _text_by_visual_rows(words_by_line: dict, line_boxes: dict) -> str:
    rows: list[list] = []
    for line_key in sorted(line_boxes, key=lambda key: (line_boxes[key][1] + line_boxes[key][3]) / 2):
        left, top, right, bottom = line_boxes[line_key]
        centre, height = (top + bottom) / 2, bottom - top
        for row in rows:
            row_left, row_top, row_right, row_bottom = row[0]
            row_centre, row_height = (row_top + row_bottom) / 2, row_bottom - row_top
            side_by_side = right <= row_left or left >= row_right
            if side_by_side and abs(centre - row_centre) <= 0.4 * min(height, row_height):
                row[0] = (min(left, row_left), min(top, row_top), max(right, row_right), max(bottom, row_bottom))
                row[1].append(line_key)
                break
        else:
            rows.append([(left, top, right, bottom), [line_key]])
    return "\n".join(" ".join(" ".join(words_by_line[key]) for key in sorted(keys, key=lambda key: line_boxes[key][0]))
                     for _box, keys in rows)


def _field_confidence(fields: dict[str, str], ocr_result: dict, word_confidences: list[float]) -> float:
    best_confidence_by_word: dict[str, float] = {}
    for word, score in zip(ocr_result["text"], ocr_result["conf"]):
        for token in re.findall(r"\w+", word.upper()):
            if float(score) >= 0:
                best_confidence_by_word[token] = max(best_confidence_by_word.get(token, 0.0), float(score))
    field_tokens = [token for value in fields.values() for token in re.findall(r"\w+", value.upper())]
    found_scores = [best_confidence_by_word[token] for token in field_tokens if token in best_confidence_by_word]
    if found_scores:
        return sum(found_scores) / len(found_scores) / 100.0
    return (sum(word_confidences) / len(word_confidences) / 100.0) if word_confidences else 0.0


def _ocr_at_size(image: Image.Image, doc_type: str, min_confidence: float) -> tuple[dict[str, str], float]:
    fields, confidence = _ocr_once(image, doc_type)
    is_complete = len(fields) >= len(DOC_FIELDS[doc_type]) and confidence >= min_confidence
    if is_complete or max(image.size) >= OCR_MIN_LONG_SIDE:
        return fields, confidence
    factor = OCR_MIN_LONG_SIDE / max(image.size)
    enlarged_size = (round(image.width * factor), round(image.height * factor))
    enlarged = image.convert("RGB").resize(enlarged_size, Image.LANCZOS)
    enlarged_fields, enlarged_confidence = _ocr_once(enlarged, doc_type)
    if (len(enlarged_fields), enlarged_confidence) > (len(fields), confidence):
        return enlarged_fields, enlarged_confidence
    return fields, confidence


def ocr_ready_image(image: Image.Image) -> Image.Image:
    if image.mode in ("I", "F"):
        lowest, highest = image.getextrema()
        scale = 255 / (highest - lowest) if highest > lowest else 1
        return image.point(lambda value: (value - lowest) * scale).convert("L")
    if image.mode not in ("1", "L", "LA", "P", "RGB", "RGBA", "I;16"):
        return image.convert("RGB")
    return image


def upright_image(image: Image.Image) -> Image.Image:
    try:
        return ImageOps.exif_transpose(image) or image
    except Exception:
        return image


def _text_line_sharpness(inverted_image: Image.Image, degrees: float) -> float:
    rotated = inverted_image.rotate(degrees, resample=Image.BILINEAR, fillcolor=0)
    row_darkness = list(rotated.resize((1, rotated.height), Image.BOX).getdata())
    mean_darkness = sum(row_darkness) / len(row_darkness)
    return sum((value - mean_darkness) ** 2 for value in row_darkness)


def estimate_skew_degrees(image: Image.Image) -> float:
    small_copy = image.convert("L")
    small_copy.thumbnail((800, 800))
    inverted_image = ImageOps.invert(ImageOps.autocontrast(small_copy))
    coarse_best = max(range(-MAX_SKEW_DEGREES, MAX_SKEW_DEGREES + 1),
                      key=lambda degrees: _text_line_sharpness(inverted_image, degrees))
    fine_candidates = [coarse_best + step / 4 for step in range(-3, 4)]
    return max(fine_candidates, key=lambda degrees: _text_line_sharpness(inverted_image, degrees))


def _rotated(image: Image.Image, degrees: float) -> Image.Image:
    return image.convert("RGB").rotate(degrees, resample=Image.BICUBIC, expand=True, fillcolor="white")


def _orientation_candidates(image: Image.Image):
    for right_angle in (0, *RIGHT_ANGLE_TURNS):
        turned = _rotated(image, right_angle) if right_angle else image
        skew_degrees = estimate_skew_degrees(turned)
        if abs(skew_degrees) >= 1:
            yield f"turned {right_angle}, straightened {skew_degrees:+.1f}", _rotated(turned, skew_degrees)
        elif right_angle:
            yield f"turned {right_angle}", turned


def ocr_document_image(image: Image.Image, doc_type: str, min_confidence: float) -> tuple[dict[str, str], float]:
    expected_field_count = len(DOC_FIELDS[doc_type])
    best_fields, best_confidence = _ocr_at_size(image, doc_type, min_confidence)
    if len(best_fields) >= expected_field_count and best_confidence >= min_confidence:
        return best_fields, best_confidence
    sparse_fields, sparse_confidence = _ocr_once(image, doc_type, SPARSE_TEXT_MODE)
    if (len(sparse_fields), sparse_confidence) > (len(best_fields), best_confidence):
        best_fields, best_confidence = sparse_fields, sparse_confidence
        logger.info("document read better as scattered text")
    if len(best_fields) >= expected_field_count and best_confidence >= min_confidence:
        return best_fields, best_confidence
    search_image = image
    if max(image.size) > ORIENTATION_SEARCH_LONG_SIDE:
        search_image = image.copy()
        search_image.thumbnail((ORIENTATION_SEARCH_LONG_SIDE, ORIENTATION_SEARCH_LONG_SIDE), Image.LANCZOS)
    for description, candidate in _orientation_candidates(search_image):
        fields, confidence = _ocr_at_size(candidate, doc_type, min_confidence)
        if (len(fields), confidence) > (len(best_fields), best_confidence):
            best_fields, best_confidence = fields, confidence
            logger.info("document read better after it was %s", description)
        if len(best_fields) >= expected_field_count and best_confidence >= min_confidence:
            break
    return best_fields, best_confidence


def extract_document(document: models.Document, rules: Rules) -> ParsedDocument:
    if document.payload_enc:
        payload = decrypt_json(document.payload_enc) or {}
        simulated_quality = payload.get("image_quality")
        fields = {name: str(value) for name, value in (payload.get("fields") or {}).items()
                  if value not in (None, "")}
        quality = float(simulated_quality) if simulated_quality is not None else None
        return ParsedDocument(fields, 1.0, "payload", quality)

    if document.purged_at or not document.storage_path:
        return ParsedDocument({}, 0.0, "none", note="document was removed (retention policy)")

    try:
        file_bytes = filecrypt.read_decrypted(document.storage_path, document.application_id)
    except filecrypt.DecryptionError as error:
        return ParsedDocument({}, 0.0, "none", note=f"stored document could not be decrypted ({error})")

    try:
        return _parse_file_bytes(document, rules, file_bytes)
    except Exception as error:
        logger.warning("could not read document %s (%s): %s", document.id, document.doc_type, type(error).__name__)
        return ParsedDocument({}, 0.0, "none", unreadable=True, note="the file could not be opened")


def _parse_file_bytes(document: models.Document, rules: Rules, file_bytes: bytes) -> ParsedDocument:
    blur_threshold = float(rules.get("extraction.blur_laplacian_min", 100))

    if file_bytes.startswith(b"%PDF"):
        import pdfplumber
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            text = "\n".join((page.extract_text() or "") for page in pdf.pages)
            if text.strip():
                return ParsedDocument(parse_text(document.doc_type, text), 0.95, "text")
            image = pdf.pages[0].to_image(resolution=200).original
    else:
        image = upright_image(Image.open(io.BytesIO(file_bytes)))
    image = ocr_ready_image(image)

    quality = quality_score(image, blur_threshold)
    if quality < float(rules.get("extraction.min_image_quality", 0.5)):
        return ParsedDocument({}, 0.0, "ocr", quality=quality, note="image is blurry")
    if not tesseract_available():
        return ParsedDocument({}, 0.0, "ocr", quality=quality, note="OCR engine (tesseract) not installed")
    min_confidence = float(rules.get("extraction.min_confidence", 0.8))
    fields, confidence = ocr_document_image(image, document.doc_type, min_confidence)
    return ParsedDocument(fields, confidence, "ocr", quality=quality)


def effective_documents(session: Session, application_id: str, data_version: int) -> dict[str, models.Document]:
    documents = session.scalars(select(models.Document).where(
        models.Document.application_id == application_id, models.Document.data_version <= data_version)
        .order_by(models.Document.id)).all()
    return {document.doc_type: document for document in documents}


def load_form(session: Session, application: models.Application) -> dict:
    version_row = session.scalars(select(models.ApplicationVersion).where(
        models.ApplicationVersion.application_id == application.id,
        models.ApplicationVersion.data_version == application.data_version)).first()
    return decrypt_json(version_row.form_data_enc) if version_row else {}


def _validate_form_fields(form: dict, business_type: str, gst_required: bool) -> list[ExtractedRow]:
    rows: list[ExtractedRow] = []
    for field_name in FORM_REQUIRED_FIELDS + (["gstin"] if gst_required else []):
        if not form.get(field_name):
            rows.append(ExtractedRow("FORM", field_name, status="MISSING",
                                     detail=f"{field_name.replace('_', ' ')} is required"))
    format_checks = {
        "pan": lambda value: validators.validate_pan(value, business_type),
        "gstin": lambda value: validators.validate_gstin(value, form.get("pan")),
        "ifsc": validators.validate_ifsc,
        "bank_account": validators.validate_account,
    }
    for field_name, check_format in format_checks.items():
        if form.get(field_name):
            is_valid, problem = check_format(form[field_name])
            rows.append(ExtractedRow("FORM", field_name, form[field_name], 1.0, "form",
                                     "VALID" if is_valid else "INVALID", problem))
    for field_name in ("legal_name", "account_holder"):
        if form.get(field_name):
            rows.append(ExtractedRow("FORM", field_name, form[field_name], 1.0, "form"))
    return rows


def _validate_document(document: models.Document, doc_type: str, form: dict, rules: Rules) -> list[ExtractedRow]:
    label = DOC_LABEL[doc_type]
    min_quality = float(rules.get("extraction.min_image_quality", 0.5))
    min_confidence = float(rules.get("extraction.min_confidence", 0.8))
    name_pass_score = float(rules.get("extraction.name_match.pass", 90))
    name_review_score = float(rules.get("extraction.name_match.review", 75))

    parsed = extract_document(document, rules)
    document.quality_score = parsed.quality

    if parsed.quality is not None and parsed.quality < min_quality:
        blurry_detail = f"{label} image is blurry (quality {parsed.quality:.2f}). Please upload a clearer copy"
        return [ExtractedRow(doc_type, "document", source=parsed.source, status="BLURRY",
                             document_id=document.id, confidence=parsed.quality, detail=blurry_detail)]

    if parsed.unreadable:
        unreadable_detail = f"{label} could not be opened (the file may be damaged). Please upload it again"
        return [ExtractedRow(doc_type, "document", source=parsed.source, status="INVALID",
                             document_id=document.id, detail=unreadable_detail)]

    if parsed.note:
        return [ExtractedRow(doc_type, "document", source=parsed.source, status="LOW_CONF",
                             document_id=document.id, detail=f"{label}: {parsed.note}; needs manual review")]

    form_values = {
        "pan": form.get("pan"),
        "name": validators.pan_holder_name(form),
        "gstin": form.get("gstin"),
        "gst_legal_name": form.get("legal_name"),
        "bank_account": form.get("bank_account"),
        "ifsc": form.get("ifsc"),
        "account_holder": form.get("account_holder"),
    }
    format_checks = {
        "pan": validators.validate_pan,
        "gstin": validators.validate_gstin,
        "ifsc": validators.validate_ifsc,
        "bank_account": validators.validate_account,
    }

    rows: list[ExtractedRow] = []
    for field_name in DOC_FIELDS[doc_type]:
        value = parsed.fields.get(field_name)

        if not value:
            photo_tip = ""
            if parsed.source == "ocr":
                photo_tip = (f". Please upload a sharp, upright photo of the whole {label}, at least "
                             f"{PHOTO_RECOMMENDED_LONG_SIDE[0]} pixels on the long side")
            rows.append(ExtractedRow(
                doc_type, field_name, source=parsed.source, status="MISSING", document_id=document.id,
                detail=f"could not read {field_name.replace('_', ' ')} from {label}{photo_tip}",
            ))
            continue

        status, detail = "VALID", ""
        form_value = form_values.get(field_name)

        if field_name in IDENTIFIER_FIELDS:
            value = validators.normalize_identifier(value)
            is_valid, problem = format_checks[field_name](value)
            if not is_valid:
                status, detail = "INVALID", f"{label}: {problem}"
            elif form_value and value != validators.normalize_identifier(form_value):
                status, detail = "CONFLICT", f"{field_name} on {label} differs from the application form"

        elif form_value:
            score = validators.name_score(value, form_value)
            if score < name_review_score:
                status = "CONFLICT"
                detail = f"name on {label} conflicts with the application form [match {score:.0f}%]"
            elif score < name_pass_score:
                status = "LOW_CONF"
                detail = f"name on {label} only partly matches the form [match {score:.0f}%]"

        if status == "VALID" and parsed.confidence < min_confidence:
            status, detail = "LOW_CONF", f"{label}: low extraction confidence {parsed.confidence:.2f}"

        rows.append(ExtractedRow(doc_type, field_name, value, parsed.confidence, parsed.source,
                                 status, detail, document.id))
    return rows


def run_extraction(session: Session, application: models.Application, rules: Rules) -> list[ExtractedRow]:
    form = {name: (validators.normalize_identifier(value) if name in IDENTIFIER_FIELDS else (value or ""))
            for name, value in load_form(session, application).items()}
    business_type = form.get("business_type", application.business_type)
    required_docs = rules.required_documents(business_type)

    rows = _validate_form_fields(form, business_type, gst_required="GST" in required_docs)
    documents = effective_documents(session, application.id, application.data_version)
    for doc_type in required_docs:
        document = documents.get(doc_type)
        if document is None:
            rows.append(ExtractedRow(doc_type, "document", status="MISSING",
                                     detail=f"{DOC_LABEL[doc_type]} is required but was not provided"))
        else:
            rows.extend(_validate_document(document, doc_type, form, rules))
    return rows


def persist_rows(session: Session, application: models.Application, rows: list[ExtractedRow]):
    session.execute(delete(models.ExtractedField).where(models.ExtractedField.application_id == application.id,
                                                        models.ExtractedField.data_version == application.data_version))
    for row in rows:
        session.add(models.ExtractedField(
            application_id=application.id, data_version=application.data_version, document_id=row.document_id,
            doc_type=row.doc_type, field_name=row.field_name,
            value_enc=encrypt_json(row.value) if row.value else None,
            value_masked=mask_field(row.field_name, row.value), confidence=row.confidence,
            source=row.source, validation_status=row.status, detail=row.detail))
