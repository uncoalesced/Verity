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

import logging
import os
import shutil
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from verity.agent.history import db_history
from verity.agent.loop import run_audit
from verity.agent.tools import Toolbox, default_toolbox, with_history
from verity.db import persist
from verity.db.models import ReviewDecision
from verity.db.session import SessionLocal
from verity.ingestion import router as ingestion
from verity.policy.library import POLICIES, PolicyConfig
from verity.policy.retrieval import search as policy_search
from verity.reporting import exceptions as reporting

log = logging.getLogger(__name__)

UPLOAD_DIR = Path(os.getenv("VERITY_UPLOAD_DIR", "./uploads"))
STATIC_DIR = Path(__file__).parent / "static"

DECISIONS = ("approved", "rejected", "needs_info")

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
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(file.filename or "upload").name
    stored = UPLOAD_DIR / f"{uuid.uuid4().hex}_{safe_name}"

    with stored.open("wb") as fh:
        shutil.copyfileobj(file.file, fh)

    triage = ingestion.route(stored)
    document = persist.record_document(session, stored, triage)

    config = app.state.config
    # Without this the duplicate-payment and threshold-splitting controls have
    # nothing to compare against and can never fire.
    tools = with_history(
        toolbox,
        db_history(session, exclude_document_id=document.id),
    )
    result = run_audit(stored, toolbox=tools, config=config, document_id=document.id)
    persist.record_extraction(session, document.id, result)
    run = persist.save_audit(session, result, config=config, document_id=document.id)
    session.commit()

    return persist.run_as_dict(run)


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
