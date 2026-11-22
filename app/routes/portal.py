from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from .. import audit, config, filecrypt, models, services, web
from ..db import session_scope
from ..domain import engine as workflow
from ..domain.rules import load_rules
from ..extraction.pipeline import DOC_LABEL

router = APIRouter(prefix="/portal")
APPLICATION_FORM_FIELDS = [
    "legal_name", "business_type", "proprietor_name", "pincode", "phone", "email",
    "pan", "gstin", "bank_account", "ifsc", "account_holder",
]
REQUIRED_FIELD_LABELS = {"legal_name": "Legal business name", "pincode": "PIN code", "pan": "PAN",
                         "bank_account": "Bank account number", "ifsc": "IFSC", "account_holder": "Account holder name"}


def current_merchant(request: Request):
    return web.need_login(request, merchant_only=True)


def _uploaded_documents(form) -> list[dict]:
    documents = []
    for doc_type in ("PAN", "GST", "BANK_PROOF"):
        upload = form.get(f"file_{doc_type}")
        if upload is not None and getattr(upload, "filename", ""):
            file_bytes = upload.file.read(config.MAX_UPLOAD_BYTES + 1)
            documents.append({"doc_type": doc_type, "file": (upload.filename, file_bytes)})
    return documents


def _document_errors(documents: list[dict], business_type: str, other_fields_have_errors: bool) -> dict:
    if business_type not in load_rules().business_types:
        return {}
    attached_doc_types = {document["doc_type"] for document in documents}
    errors = {}
    for doc_type in load_rules().required_documents(business_type):
        if doc_type not in attached_doc_types:
            errors[f"file_{doc_type}"] = f"{DOC_LABEL[doc_type][0].upper()}{DOC_LABEL[doc_type][1:]} is required."
        elif other_fields_have_errors:
            errors[f"file_{doc_type}"] = "Please choose this file again."
    return errors


def _form_values(form) -> dict:
    return {field_name: (form.get(field_name) or "").strip() for field_name in APPLICATION_FORM_FIELDS}


@router.get("")
def dashboard(request: Request):
    merchant = current_merchant(request)
    with session_scope() as session:
        applications = services.my_applications(session, merchant.user_id)
    return web.render(request, "portal/dashboard.html", applications=applications)


@router.get("/new")
def new_application_form(request: Request):
    merchant = current_merchant(request)
    return web.render(request, "portal/new.html", values={"business_type": "company", "email": merchant.email},
                      errors={})


@router.post("/new")
async def submit_application(request: Request):
    merchant = current_merchant(request)
    form = await web.checked_form(request)
    form_values = _form_values(form)
    errors = {field_name: f"{label} is required." for field_name, label in REQUIRED_FIELD_LABELS.items()
              if not form_values[field_name]}
    if form_values["business_type"] not in load_rules().business_types:
        errors["business_type"] = "Please choose a business type from the list."
    if form_values["business_type"] != "individual" and not form_values["gstin"]:
        errors["gstin"] = "GSTIN is required for this business type."
    if form_values["business_type"] == "individual" and not form_values["proprietor_name"]:
        errors["proprietor_name"] = "Owner's name (exactly as on the PAN card) is required for sole proprietors."
    documents = _uploaded_documents(form)
    errors.update(_document_errors(documents, form_values["business_type"], other_fields_have_errors=bool(errors)))
    if errors:
        return web.render(request, "portal/new.html", status_code=422, values=form_values, errors=errors)
    try:
        with session_scope() as session:
            application, _created = services.create_application(
                session, {"form": form_values, "documents": documents}, actor=f"merchant:{merchant.user_id}",
                owner_id=merchant.user_id, allow_scenarios=False,
                allow_structured_documents=False)
            application_id = application.id
    except services.ValidationFailed as error:
        return web.render(request, "portal/new.html", status_code=422, values=form_values, errors={"files": str(error)})
    return web.redirect(f"/portal/applications/{application_id}",
                        "Application submitted. We're checking your documents now.")


@router.get("/applications/{application_id}")
def application_page(request: Request, application_id: str, fragment: bool = False):
    merchant = current_merchant(request)
    with session_scope() as session:
        try:
            application = services.owned_application(session, application_id, merchant.user_id)
        except KeyError:
            raise HTTPException(404, "Application not found")
        view = services.merchant_view(session, application)
    rules = load_rules()
    template_name = "portal/_status.html" if fragment else "portal/application.html"
    return web.render(request, template_name, view=view,
                      retention=rules.get("retention", {}),
                      required_docs=rules.required_documents(view["business_type"]))


@router.post("/applications/{application_id}/update")
async def update_application(request: Request, application_id: str):
    merchant = current_merchant(request)
    form = await web.checked_form(request)
    changed_values = {field_name: value for field_name, value in _form_values(form).items() if value}
    try:
        with session_scope() as session:
            services.owned_application(session, application_id, merchant.user_id)
            documents = _uploaded_documents(form)
            _application, was_changed = services.submit_changes(session, application_id, changed_values, documents,
                                                                actor=f"merchant:{merchant.user_id}",
                                                                allow_structured_documents=False)
    except KeyError:
        raise HTTPException(404, "Application not found")
    except (services.ValidationFailed, workflow.ConflictError) as error:
        return web.redirect(f"/portal/applications/{application_id}", str(error), "danger")
    if not was_changed:
        return web.redirect(f"/portal/applications/{application_id}", "Nothing was changed.", "info")
    return web.redirect(f"/portal/applications/{application_id}", "Thanks! We're re-checking your updated details.")


@router.post("/applications/{application_id}/withdraw")
async def withdraw_application(request: Request, application_id: str):
    merchant = current_merchant(request)
    await web.checked_form(request)
    try:
        with session_scope() as session:
            services.owned_application(session, application_id, merchant.user_id)
            services.withdraw_application(session, application_id, f"merchant:{merchant.user_id}")
    except KeyError:
        raise HTTPException(404, "Application not found")
    except workflow.ConflictError as error:
        return web.redirect(f"/portal/applications/{application_id}", str(error), "danger")
    return web.redirect(f"/portal/applications/{application_id}", "Application withdrawn.", "info")


@router.get("/applications/{application_id}/documents/{document_id}")
def download_document(request: Request, application_id: str, document_id: int):
    merchant = current_merchant(request)
    with session_scope() as session:
        try:
            services.owned_application(session, application_id, merchant.user_id)
        except KeyError:
            raise HTTPException(404, "Not found")
        document = session.get(models.Document, document_id)
        if document is None or document.application_id != application_id or not document.storage_path:
            raise HTTPException(404, "Document not available")
        try:
            file_bytes = services.read_document(document)
        except filecrypt.DecryptionError:
            raise HTTPException(410, "This document is no longer available.")
        audit.record(session, application_id, f"merchant:{merchant.user_id}", "DOCUMENT_DOWNLOADED",
                     payload={"doc_type": document.doc_type})
        download_name = document.filename
        content_type = services.CONTENT_TYPES.get(document.content_type or "", "application/octet-stream")
    return Response(file_bytes, media_type=content_type,
                    headers={"Content-Disposition": f'attachment; filename="{download_name}"'})


@router.get("/my-data")
def my_data_page(request: Request):
    merchant = current_merchant(request)
    with session_scope() as session:
        applications = services.my_applications(session, merchant.user_id)
    return web.render(request, "portal/my_data.html", applications=applications)
