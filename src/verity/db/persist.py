"""Writing an audit down.

`run_audit` produces an `AuditResult` in memory. This module is the one place
that turns it into rows. Keeping it out of the loop means the agent has no
database dependency at all -- it can run in a test, in a batch job, or against a
file on somebody's desktop, and persistence is a decision the caller makes
afterwards.

One rule holds throughout: a run is saved whole or not at all. The verdict, the
findings that justify it and the steps that produced it go in one transaction,
because a verdict stored without its findings is worse than no record.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from verity.agent.loop import AuditResult
from verity.db.models import AuditRun, Document, Extraction
from verity.db.models import Finding as FindingRow
from verity.db.models import TraceStep as TraceStepRow
from verity.ingestion.router import TriageResult
from verity.obs.trace import _jsonable
from verity.policy.library import PolicyConfig
from verity.policy.rules import worst_severity


def record_document(session: Session, path: str | Path, triage: TriageResult) -> Document:
    """Insert the intake record for one file. Flushed, not committed."""
    path = Path(path)
    document = Document(
        source_path=str(path),
        filename=path.name,
        format=triage.format,
        ingestion_status=triage.status,
        reject_reason=triage.reason,
    )
    session.add(document)
    session.flush()
    return document


def record_extraction(session: Session, document_id: int, result: AuditResult) -> Extraction | None:
    """Store the reading itself on the Month 1 table.

    Skipped for a document that was never read -- a row full of nulls would look
    like a document that was read and found to be empty.
    """
    if result.ingestion_status != "accepted":
        return None

    fields = result.fields
    extraction = Extraction(
        document_id=document_id,
        vendor=fields.vendor,
        line_items=[item.as_dict() for item in fields.line_items],
        total=fields.total,
        date=fields.date,
        signature_present=fields.signature_present,
        confidence=fields.confidence,
    )
    session.add(extraction)
    session.flush()
    return extraction


def _as_json(value: object) -> dict | None:
    """Trace payloads are stored as JSON objects; anything else is wrapped.

    The column is JSON, so a bare list or string would still store, but wrapping
    keeps every row the same shape to query.
    """
    converted = _jsonable(value)
    if converted is None:
        return None
    return converted if isinstance(converted, dict) else {"value": converted}


def save_audit(
    session: Session,
    result: AuditResult,
    *,
    config: PolicyConfig | None = None,
    document_id: int | None = None,
) -> AuditRun:
    """Persist one audit -- verdict, findings and trace -- as a single unit.

    Flushes so the caller gets the assigned ids back; committing is left to the
    caller, who owns the transaction boundary.
    """
    trace = result.trace
    run = AuditRun(
        run_id=trace.run_id,
        document_id=document_id if document_id is not None else result.document_id,
        filename=result.filename,
        verdict=result.verdict,
        worst_severity=worst_severity(result.findings),
        ingestion_status=result.ingestion_status,
        reject_reason=result.reject_reason,
        fields=result.fields.as_dict(),
        config=config.as_dict() if config else None,
        started_at=trace.started_at,
        finished_at=trace.finished_at,
        duration_ms=trace.duration_ms,
    )
    run.findings = [
        FindingRow(
            rule_id=f.rule_id,
            severity=f.severity,
            message=f.message,
            evidence=f.evidence,
            policy_title=f.policy_title,
            policy_text=f.policy_text,
        )
        for f in result.findings
    ]
    run.steps = [
        TraceStepRow(
            step_index=step.index,
            tool=step.tool,
            args=_as_json(step.args),
            result=_as_json(step.result),
            ok=step.ok,
            error=step.error,
            duration_ms=step.duration_ms,
            started_at=step.started_at,
            note=step.note,
        )
        for step in trace.steps
    ]

    session.add(run)
    session.flush()
    return run


def load_run(session: Session, run_id: str) -> AuditRun | None:
    """Fetch one run with its findings, steps and review decisions loaded."""
    stmt = (
        select(AuditRun)
        .where(AuditRun.run_id == run_id)
        .options(
            selectinload(AuditRun.findings),
            selectinload(AuditRun.steps),
            selectinload(AuditRun.reviews),
        )
    )
    return session.execute(stmt).scalar_one_or_none()


def recent_runs(session: Session, limit: int = 50, verdict: str | None = None) -> list[AuditRun]:
    """The audit queue, newest first, optionally narrowed to one verdict."""
    stmt = (
        select(AuditRun)
        .options(selectinload(AuditRun.findings), selectinload(AuditRun.reviews))
        .order_by(AuditRun.id.desc())
        .limit(limit)
    )
    if verdict:
        stmt = stmt.where(AuditRun.verdict == verdict)
    return list(session.execute(stmt).scalars())


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if value else None


def latest_review(run: AuditRun):
    """The decision that currently stands on this run, or None if untouched.

    Decisions are append-only, so "current" means "most recent" rather than "the
    one row we kept". An overturned decision stays visible in the history.
    """
    if not run.reviews:
        return None
    return max(run.reviews, key=lambda r: (r.decided_at, r.id))


def review_as_dict(review) -> dict | None:
    if review is None:
        return None
    return {
        "decision": review.decision,
        "reviewer": review.reviewer,
        "rationale": review.rationale,
        "decided_at": _iso(review.decided_at),
        "overrides_verdict": review.overrides_verdict,
    }


def finding_as_dict(finding: FindingRow) -> dict:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "message": finding.message,
        "evidence": finding.evidence,
        "policy_title": finding.policy_title,
        "policy_text": finding.policy_text,
    }


def run_as_dict(run: AuditRun, include_trace: bool = True) -> dict:
    """The API shape for one stored run."""
    data = {
        "run_id": run.run_id,
        "document_id": run.document_id,
        "filename": run.filename,
        "verdict": run.verdict,
        "worst_severity": run.worst_severity,
        "ingestion_status": run.ingestion_status,
        "reject_reason": run.reject_reason,
        "fields": run.fields,
        "config": run.config,
        "started_at": _iso(run.started_at),
        "finished_at": _iso(run.finished_at),
        "duration_ms": run.duration_ms,
        "findings": [finding_as_dict(f) for f in run.findings],
        "review": review_as_dict(latest_review(run)),
    }
    if include_trace:
        data["trace"] = [
            {
                "index": s.step_index,
                "tool": s.tool,
                "args": s.args,
                "result": s.result,
                "ok": s.ok,
                "error": s.error,
                "duration_ms": s.duration_ms,
                "started_at": _iso(s.started_at),
                "note": s.note,
            }
            for s in run.steps
        ]
    return data
