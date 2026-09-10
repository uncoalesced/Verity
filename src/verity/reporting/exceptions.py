"""The exception report and the audit pack.

Two artefacts, one purpose: getting the audit out of the system and into the
hands of someone who does not use the system.

* The exception report is a flat CSV of everything held. It goes to the AP
  manager, who opens it in Excel and works the queue.
* The audit pack is one document rendered whole -- the verdict, every control
  that fired with the policy language it fired under, the fields that were
  read, the reviewer decision, and the agent trace. It goes in the file when
  an external auditor asks how a payment came to be released.

Neither format is clever. Cleverness in a reporting layer is how numbers stop
matching between two views of the same thing.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Sequence

from verity.db.persist import finding_as_dict, latest_review, review_as_dict
from verity.policy.rules import worst_severity as _worst

# One row per held document, not one row per finding: the AP manager works
# documents. The rules that fired are collapsed into a single cell.
COLUMNS = (
    "run_id",
    "filename",
    "verdict",
    "worst_severity",
    "rule_ids",
    "vendor",
    "total",
    "date",
    "confidence",
    "reviewed",
    "reviewer",
    "decision",
    "overrides_verdict",
    "audited_at",
)


def _field(run, name: str):
    fields = run.fields or {}
    return fields.get(name)


def exception_row(run) -> dict:
    """Flatten one stored run into the report row."""
    review = latest_review(run)
    return {
        "run_id": run.run_id,
        "filename": run.filename,
        "verdict": run.verdict,
        "worst_severity": run.worst_severity or "",
        "rule_ids": " ".join(f.rule_id for f in run.findings),
        "vendor": _field(run, "vendor") or "",
        "total": _field(run, "total") or "",
        "date": _field(run, "date") or "",
        "confidence": _field(run, "confidence") or "",
        "reviewed": "yes" if review else "no",
        "reviewer": review.reviewer if review else "",
        "decision": review.decision if review else "",
        "overrides_verdict": "yes" if review and review.overrides_verdict else "",
        "audited_at": run.started_at.isoformat() if run.started_at else "",
    }


def row_from_result(result) -> dict:
    """The same report row, built from an in-memory `AuditResult`.

    A batch run that has not been saved still has to produce the identical
    columns, or the dry-run report and the stored report disagree about the same
    documents -- which is how a reporting layer loses people's trust.
    """
    fields = result.fields
    return {
        "run_id": result.trace.run_id,
        "filename": result.filename,
        "verdict": result.verdict,
        "worst_severity": _worst(result.findings) or "",
        "rule_ids": " ".join(f.rule_id for f in result.findings),
        "vendor": fields.vendor or "",
        "total": "" if fields.total is None else str(fields.total),
        "date": fields.date.isoformat() if fields.date else "",
        "confidence": round(fields.confidence, 4),
        # Nothing in memory has been reviewed yet, by definition.
        "reviewed": "no",
        "reviewer": "",
        "decision": "",
        "overrides_verdict": "",
        "audited_at": result.trace.started_at.isoformat(),
    }


def results_to_csv(results: Iterable, held_only: bool = True) -> str:
    """The exception report for a batch that has not been persisted."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(COLUMNS), extrasaction="ignore")
    writer.writeheader()
    for result in results:
        if held_only and result.verdict == "pass":
            continue
        writer.writerow(row_from_result(result))
    return buffer.getvalue()


def exception_rows(runs: Iterable, held_only: bool = True) -> list[dict]:
    """Report rows for the given runs.

    `held_only` keeps the report to what needs action. Passing False produces
    the full population, which is what an auditor sampling a period wants.
    """
    rows = []
    for run in runs:
        if held_only and run.verdict == "pass":
            continue
        rows.append(exception_row(run))
    return rows


def to_csv(runs: Iterable, held_only: bool = True, columns: Sequence[str] = COLUMNS) -> str:
    """The exception report as CSV text.

    Written with the csv module rather than string joining, so a supplier name
    containing a comma does not silently shift every later column.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(columns), extrasaction="ignore")
    writer.writeheader()
    for row in exception_rows(runs, held_only=held_only):
        writer.writerow(row)
    return buffer.getvalue()


def audit_pack(run, include_trace: bool = True) -> dict:
    """Everything about one run, in the order a reviewer reads it."""
    pack = {
        "run_id": run.run_id,
        "filename": run.filename,
        "verdict": run.verdict,
        "worst_severity": run.worst_severity,
        "audited_at": run.started_at.isoformat() if run.started_at else None,
        "duration_ms": run.duration_ms,
        "ingestion_status": run.ingestion_status,
        "reject_reason": run.reject_reason,
        "fields_read": run.fields,
        "thresholds_in_force": run.config,
        "findings": [finding_as_dict(f) for f in run.findings],
        "review": review_as_dict(latest_review(run)),
        "review_history": [
            review_as_dict(r) for r in sorted(run.reviews, key=lambda r: r.id)
        ],
    }
    if include_trace:
        pack["trace"] = [
            {
                "index": s.step_index,
                "tool": s.tool,
                "ok": s.ok,
                "error": s.error,
                "duration_ms": s.duration_ms,
                "note": s.note,
            }
            for s in run.steps
        ]
    return pack


def summarise(runs: Sequence) -> dict:
    """Period totals: how much was held, and which controls did the holding."""
    by_verdict: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    overrides = 0
    for run in runs:
        by_verdict[run.verdict] = by_verdict.get(run.verdict, 0) + 1
        for finding in run.findings:
            by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
        review = latest_review(run)
        if review and review.overrides_verdict:
            overrides += 1
    return {
        "documents": len(runs),
        "by_verdict": by_verdict,
        "by_rule": dict(sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))),
        "reviewer_overrides": overrides,
    }
