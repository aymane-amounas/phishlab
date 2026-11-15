"""FastAPI routes. The API is the trusted boundary; uploads are hostile input."""

from __future__ import annotations

from fastapi import APIRouter, Body, File, Form, HTTPException, Response, UploadFile

from phishlab.cases import DISPOSITIONS, CaseStore
from phishlab.config import settings
from phishlab.engine import analyze_artifact
from phishlab.ingestion import IngestionError, ingest_bytes, ingest_text
from phishlab.network import NetworkDisabled, inspect_redirects
from phishlab.reporting import build_json_report, build_pdf_report

router = APIRouter(prefix="/api")
_store: CaseStore | None = None


def get_store() -> CaseStore:
    global _store
    if _store is None:
        _store = CaseStore()
    return _store


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "network_lookups_enabled": settings.network_lookups_enabled}


@router.post("/analyze")
async def analyze(
    file: UploadFile | None = File(default=None),
    headers: str | None = Form(default=None),
    text: str | None = Form(default=None),
) -> dict:
    artifact = await _artifact_from_inputs(file, headers, text)
    return analyze_artifact(artifact)


@router.post("/cases")
async def create_case(
    file: UploadFile | None = File(default=None),
    headers: str | None = Form(default=None),
    text: str | None = Form(default=None),
) -> dict:
    artifact = await _artifact_from_inputs(file, headers, text)
    analysis = analyze_artifact(artifact)
    cid = get_store().create(analysis)
    return {"id": cid, "analysis": analysis}


@router.get("/cases")
def list_cases(
    q: str | None = None,
    disposition: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    items = get_store().list(
        q=q, disposition=disposition, severity=severity, limit=min(limit, 500), offset=offset
    )
    return {"items": [item.__dict__ for item in items]}


@router.get("/stats")
def stats() -> dict:
    return get_store().stats()


@router.get("/cases/{cid}")
def get_case(cid: str) -> dict:
    case = get_store().get(cid)
    if not case:
        raise HTTPException(404, "Case not found")
    return case


@router.patch("/cases/{cid}/disposition")
def set_disposition(cid: str, payload: dict = Body(...)) -> dict:
    disposition = payload.get("disposition", "")
    if disposition not in DISPOSITIONS:
        raise HTTPException(400, f"Invalid disposition. One of: {sorted(DISPOSITIONS)}")
    if not get_store().update_disposition(cid, disposition, payload.get("rationale")):
        raise HTTPException(404, "Case not found")
    return {"ok": True}


@router.patch("/cases/{cid}/notes")
def set_notes(cid: str, payload: dict = Body(...)) -> dict:
    if not get_store().update_notes(cid, str(payload.get("notes", ""))):
        raise HTTPException(404, "Case not found")
    return {"ok": True}


@router.delete("/cases/{cid}")
def delete_case(cid: str) -> dict:
    if not get_store().delete(cid):
        raise HTTPException(404, "Case not found")
    return {"ok": True}


@router.get("/cases/{cid}/report.json")
def report_json(cid: str, redact: bool = True) -> dict:
    case = get_store().get(cid)
    if not case:
        raise HTTPException(404, "Case not found")
    return build_json_report(case, redact=redact)


@router.get("/cases/{cid}/report.pdf")
def report_pdf(cid: str, redact: bool = True) -> Response:
    case = get_store().get(cid)
    if not case:
        raise HTTPException(404, "Case not found")
    pdf = build_pdf_report(case, redact=redact)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="phishlab-{cid[:8]}.pdf"'},
    )


@router.post("/url/inspect")
def url_inspect(payload: dict = Body(...)) -> dict:
    url = str(payload.get("url", ""))
    try:
        return inspect_redirects(url)
    except NetworkDisabled as exc:
        raise HTTPException(409, str(exc)) from exc
    except NotImplementedError as exc:
        raise HTTPException(501, str(exc)) from exc


async def _artifact_from_inputs(file, headers, text):
    try:
        if file is not None:
            data = await file.read(settings.max_upload_bytes + 1)
            if len(data) > settings.max_upload_bytes:
                raise IngestionError("Upload exceeds size limit.")
            return ingest_bytes(data, source_kind="eml", declared_filename=file.filename)
        if headers:
            return ingest_text(headers, source_kind="headers")
        if text:
            return ingest_text(text, source_kind="text")
    except IngestionError as exc:
        raise HTTPException(400, str(exc)) from exc
    raise HTTPException(400, "Provide a file, headers, or text.")
