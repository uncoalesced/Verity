"""The HTTP surface.

Thin on purpose. Every endpoint does the same three things: take the request
apart, call something in `verity.agent` or `verity.db`, and turn the answer into
JSON. No policy logic lives here, so there is exactly one place where a control
is defined and exactly one place it can drift from.

The two dependencies -- the database session and the agent toolbox -- are
injected rather than imported, which is what lets the whole API be tested
against SQLite and fake models in under a second, with no checkpoint download
and no Postgres.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import logging
import os
import shutil
import uuid
from decimal import Decimal
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from verity.agent.history import db_history
from verity.agent.loop import AuditResult, run_audit
from verity.agent.tools import Toolbox, default_toolbox, with_history
from verity.db import persist
from verity.db.models import Document, ReviewDecision
from verity.db.session import SessionLocal
from verity.extraction.schema import ExtractedFields, LineItem
from verity.ingestion import router as ingestion
from verity.policy.library import POLICIES, PolicyConfig
from verity.policy.retrieval import search as policy_search
from verity.reporting import exceptions as reporting

log = logging.getLogger(__name__)

UPLOAD_DIR = Path(os.getenv("VERITY_UPLOAD_DIR", "./uploads"))
STATIC_DIR = Path(__file__).parent / "static"

DECISIONS = ("approved", "rejected", "needs_info")

# A base64 body is decoded in memory before intake ever sees it, so the size
# ceiling has to be checked on the encoded string rather than left to the
# 25 MB limit in `verity.ingestion.router`. Base64 costs 4 bytes per 3.
MAX_BASE64_CHARS = 4 * ((ingestion.MAX_BYTES + 2) // 3)

app = FastAPI(
    title="Verity",
    version="0.3.0",
    description="Document compliance and fraud auditing for accounts payable.",
)

# Overridable at import time by tests and by anything embedding the app.
app.state.session_factory = SessionLocal
app.state.toolbox = None
app.state.config = PolicyConfig()


def get_session():
    session = app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


def get_toolbox() -> Toolbox:
    """The real models unless something has substituted a toolbox."""
    if app.state.toolbox is None:
        app.state.toolbox = default_toolbox()
    return app.state.toolbox


class ReviewIn(BaseModel):
    """A human decision on a held document."""

    decision: str = Field(description="approved | rejected | needs_info")
    reviewer: str = Field(min_length=1, max_length=255)
    rationale: str | None = None


class LineItemIn(BaseModel):
    """One row of a document, as an outside caller reports it."""

    name: str = Field(max_length=500)
    quantity: Decimal | None = None
    unit_price: Decimal | None = None
    amount: Decimal | None = Field(default=None, description="Extended price for the row.")


class FieldsIn(BaseModel):
    """A reading somebody else already did.

    Mirrors `verity.extraction.schema.ExtractedFields`. Anything the caller
    could not read must be left out or sent as null -- a zero total and an
    unread total lead to opposite verdicts, so the two are never merged here.
    """

    vendor: str | None = None
    date: dt.date | None = None
    total: Decimal | None = None
    subtotal: Decimal | None = None
    tax: Decimal | None = None
    line_items: list[LineItemIn] = Field(default_factory=list)
    signature_present: bool | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    def as_fields(self) -> ExtractedFields:
        return ExtractedFields(
            vendor=self.vendor,
            date=self.date,
            total=self.total,
            subtotal=self.subtotal,
            tax=self.tax,
            line_items=[
                LineItem(
                    name=item.name,
                    quantity=item.quantity,
                    unit_price=item.unit_price,
                    amount=item.amount,
                )
                for item in self.line_items
            ],
            signature_present=self.signature_present,
            confidence=self.confidence,
            raw=self.model_dump(mode="json"),
        )


class AuditIn(BaseModel):
    """One document to audit, as JSON.

    Two ways to send it, and exactly one of them per request:

    * `content_base64` -- the file itself. Verity reads it, which needs the
      extraction models on the server.
    * `fields` -- a reading the caller already did. No model runs; the controls
      are applied to the numbers as given.

    The distinction matters when reading the answer: on a `fields` request the
    confidence score reported back is the caller's own, not Verity's.
    """

    filename: str = Field(default="document", max_length=255)
    content_base64: str | None = None
    fields: FieldsIn | None = None

    @model_validator(mode="after")
    def exactly_one_payload(self) -> AuditIn:
        if (self.content_base64 is None) == (self.fields is None):
            raise ValueError("send exactly one of content_base64 or fields")
        return self


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "controls": len(POLICIES)}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    """The review queue."""
    page = STATIC_DIR / "index.html"
    if not page.is_file():
        raise HTTPException(status_code=404, detail="UI not installed")
    return page.read_text(encoding="utf-8")


@app.get("/policies")
def list_policies() -> dict:
    """The control library, as written. This is the document a finance team owns."""
    return {
        "controls": [
            {
                "id": p.id,
                "title": p.title,
                "text": p.text,
                "severity": p.severity,
                "category": p.category,
            }
            for p in POLICIES
        ]
    }


@app.get("/policies/search")
def search_policies(q: str = Query(min_length=1), k: int = Query(default=3, ge=1, le=20)) -> dict:
    """Ask the control library a question in your own words.

    Search never decides anything. Every control runs on every document
    regardless of what this returns -- see verity.policy.retrieval.
    """
    return {"query": q, "hits": [hit.as_dict() for hit in policy_search(q, k=k)]}


def _stored_path(filename: str | None) -> Path:
    """A collision-proof path under the upload directory for one filename."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(filename or "upload").name
    return UPLOAD_DIR / f"{uuid.uuid4().hex}_{safe_name}"


def _ledger(toolbox: Toolbox, session: Session, document: Document) -> Toolbox:
    """Bind the ledger lookup this document should be compared against.

    Without it the duplicate-payment (P-002) and threshold-splitting (P-011)
    controls have nothing to compare against and can never fire.
    """
    return with_history(toolbox, db_history(session, exclude_document_id=document.id))


def _store(session: Session, document: Document, result: AuditResult, config: PolicyConfig) -> dict:
    """Write one finished audit down and return it in the API's shape.

    Both entry points end here, so a run recorded through the JSON endpoint is
    the same row, with the same trace, as one recorded through the upload form.
    """
    persist.record_extraction(session, document.id, result)
    run = persist.save_audit(session, result, config=config, document_id=document.id)
    session.commit()
    return persist.run_as_dict(run)


@app.post("/documents", status_code=201)
def upload_document(
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
    toolbox: Toolbox = Depends(get_toolbox),
) -> dict:
    """Take one file, audit it, store the result, return the verdict.

    The upload is written to disk before anything reads it, so the intake router
    sees the same bytes that were stored rather than a stream that has already
    been consumed.
    """
    stored = _stored_path(file.filename)
    with stored.open("wb") as fh:
        shutil.copyfileobj(file.file, fh)

    triage = ingestion.route(stored)
    document = persist.record_document(session, stored, triage)

    config = app.state.config
    result = run_audit(
        stored,
        toolbox=_ledger(toolbox, session, document),
        config=config,
        document_id=document.id,
    )
    return _store(session, document, result, config)


@app.post("/audit", status_code=201, operation_id="audit_document")
def audit_document(
    body: AuditIn,
    session: Session = Depends(get_session),
    toolbox: Toolbox = Depends(get_toolbox),
) -> dict:
    """Audit one document sent as JSON, and store the run.

    This is the endpoint an outside agent calls -- the MCP tool in
    `verity.mcp_server` and the ChatGPT Actions schema both come out of it.
    `POST /documents` does the same job for a browser form; the two differ only
    in how the bytes arrive, and both run the same audit and write the same row.

    The answer carries the verdict, every finding with the policy text it fired
    under quoted in full, the fields the verdict was reached on, the thresholds
    in force, and the trace.
    """
    config = app.state.config

    if body.content_base64 is not None:
        stored = _stored_path(body.filename)
        stored.write_bytes(_decode(body.content_base64))
        triage = ingestion.route(stored)
        document = persist.record_document(session, stored, triage)
        result = run_audit(
            stored,
            toolbox=_ledger(toolbox, session, document),
            config=config,
            document_id=document.id,
        )
        return _store(session, document, result, config)

    # A reading the caller did itself. Nothing was uploaded, so the intake
    # record names the payload rather than a file on disk, and triage is
    # recorded as accepted because there was no file to reject.
    name = Path(body.filename).name or "document"
    triage = ingestion.TriageResult(path=Path(name), status=ingestion.ACCEPTED)
    document = persist.record_document(session, name, triage)
    result = run_audit(
        name,
        toolbox=_ledger(toolbox, session, document),
        config=config,
        document_id=document.id,
        fields=body.fields.as_fields(),
    )
    return _store(session, document, result, config)


def _decode(content_base64: str) -> bytes:
    """Turn the request's base64 back into bytes, or refuse it.

    A trust boundary: the length is checked before anything is decoded, so an
    oversized body is refused rather than expanded in memory first.
    """
    if len(content_base64) > MAX_BASE64_CHARS:
        raise HTTPException(
            status_code=413,
            detail=f"document exceeds the {ingestion.MAX_BYTES} byte limit",
        )
    try:
        return base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"content_base64 is not base64: {exc}") from exc


@app.get("/runs")
def list_runs(
    limit: int = Query(default=50, ge=1, le=500),
    verdict: str | None = Query(default=None),
    session: Session = Depends(get_session),
) -> dict:
    runs = persist.recent_runs(session, limit=limit, verdict=verdict)
    return {
        "runs": [persist.run_as_dict(run, include_trace=False) for run in runs],
        "summary": reporting.summarise(runs),
    }


@app.get("/runs/{run_id}")
def get_run(run_id: str, session: Session = Depends(get_session)) -> dict:
    run = persist.load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="no such run")
    return persist.run_as_dict(run)


@app.get("/runs/{run_id}/pack")
def get_audit_pack(run_id: str, session: Session = Depends(get_session)) -> dict:
    """One document rendered whole, for the audit file."""
    run = persist.load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="no such run")
    return reporting.audit_pack(run)


@app.post("/runs/{run_id}/review", status_code=201)
def review_run(
    run_id: str,
    body: ReviewIn,
    session: Session = Depends(get_session),
) -> dict:
    """Record what a person decided.

    Decisions are appended, never edited. Clearing a document the controls
    blocked is allowed and is recorded as an override, because a control system
    that cannot be overridden gets worked around instead of used.
    """
    if body.decision not in DECISIONS:
        raise HTTPException(status_code=422, detail=f"decision must be one of {DECISIONS}")

    run = persist.load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="no such run")

    decision = ReviewDecision(
        audit_run_id=run.id,
        decision=body.decision,
        reviewer=body.reviewer,
        rationale=body.rationale,
        overrides_verdict=body.decision == "approved" and run.verdict == "blocked",
    )
    session.add(decision)
    session.commit()
    # The run is already loaded in this session with its review collection as it
    # was a moment ago. Expire it, or the response omits the decision that was
    # just recorded -- which is exactly the field the caller is checking.
    session.expire_all()

    run = persist.load_run(session, run_id)
    return persist.run_as_dict(run, include_trace=False)


@app.get("/reports/exceptions.csv", response_class=PlainTextResponse)
def exceptions_csv(
    limit: int = Query(default=500, ge=1, le=5000),
    held_only: bool = Query(default=True),
    session: Session = Depends(get_session),
) -> str:
    """The queue as a spreadsheet."""
    runs = persist.recent_runs(session, limit=limit)
    return reporting.to_csv(runs, held_only=held_only)


@app.get("/reports/summary")
def reports_summary(
    limit: int = Query(default=500, ge=1, le=5000),
    session: Session = Depends(get_session),
) -> dict:
    return reporting.summarise(persist.recent_runs(session, limit=limit))
