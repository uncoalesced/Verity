"""The orchestrator: one document in, one audited decision out.

This is the only place that knows the *order* things happen in. Every step is
a call into a `Toolbox` (see `verity.agent.tools`), so any of them can be
swapped for a test double or a cheaper stand-in, and every call is wrapped in
a `Trace` (see `verity.obs.trace`) so a failure is recorded rather than
silently absorbed.

The loop makes exactly one policy decision per document. It does not retry
and it does not fall back to a cheaper answer without saying so.

Ordering, and why this is a loop and not five independent pipeline stages:

1. triage            -- reject bad files before spending a model call on them
2. load_image        -- get a page image, or stop; nothing downstream reads bytes
3. read_fields        -- the one expensive multimodal read
4. detect_signature   -- optional; only worth running once a page is confirmed readable
5. history            -- needs the vendor/total/date that step 3 just produced
6. rules.evaluate     -- the only step that is pure and deterministic; every
   step above it exists only to build the `AuditContext` this one consumes

Two failure modes are treated differently, on purpose:

* `PageLoadError` is a *documented* shape of bad input -- a file that passed
  triage (it decodes, it has content) but that the pipeline still cannot turn
  into a page image (a born-digital PDF with no embedded image, today). That
  is not infrastructure breaking; it is another way for a document to be
  unauditable, so it is folded into the same P-014 "rejected at intake"
  finding that a bad file gets, and `run_audit` returns a normal `AuditResult`
  rather than raising.
* Anything else that raises out of a tool call -- a model server down, a
  corrupt checkpoint, a database outage -- is *not* folded into a rejection
  finding. Reporting "this document was rejected" when the real story is "the
  extraction model crashed" would misattribute an infrastructure failure as a
  document-quality one, which is exactly the kind of plausible-looking wrong
  answer the trace exists to prevent. The trace records the failed step; the
  exception propagates; the caller decides whether to retry.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass
from pathlib import Path

from verity.agent.tools import PageLoadError, Toolbox, default_toolbox
from verity.extraction.schema import ExtractedFields
from verity.ingestion.router import ACCEPTED, REJECTED
from verity.obs.trace import Trace
from verity.policy import rules
from verity.policy.library import PolicyConfig
from verity.policy.rules import AuditContext, Finding

log = logging.getLogger(__name__)


@dataclass
class AuditResult:
    """What one call to `run_audit` produces: the decision plus its receipts.

    `fields`, `config` and `trace` are kept alongside the verdict rather than
    discarded once the findings are computed -- a reviewer asking "why was
    this held" needs the fields that were actually read and the thresholds
    that were in force, and an engineer asking "what did the pipeline
    actually do" needs the trace. Neither should require re-running the
    audit. `verity.db.persist.save_audit` writes all of this to the
    `audit_runs` / `findings` / `trace_steps` tables for exactly that reason.
    """

    filename: str
    verdict: str
    findings: list[Finding]
    fields: ExtractedFields
    config: PolicyConfig
    ingestion_status: str
    reject_reason: str | None
    trace: Trace
    document_id: int | None = None

    @property
    def ok(self) -> bool:
        """False when some step in the trace raised.

        This is independent of `verdict` -- a document can be legitimately
        `blocked` (a clean run that found a real problem) while `ok` is True,
        and a run can be `ok=False` while still producing a verdict, when the
        failure was the documented `PageLoadError` case above.
        """
        return not self.trace.failed_steps

    def as_dict(self) -> dict:
        return {
            "document_id": self.document_id,
            "filename": self.filename,
            "verdict": self.verdict,
            "findings": [f.as_dict() for f in self.findings],
            "fields": self.fields.as_dict(),
            "config": self.config.as_dict(),
            "ingestion_status": self.ingestion_status,
            "reject_reason": self.reject_reason,
            "trace": self.trace.as_dict(),
        }


def _triage_step_result(triage) -> dict:
    return {"status": triage.status, "format": triage.format, "reason": triage.reason}


def run_audit(
    path: str | Path,
    *,
    toolbox: Toolbox | None = None,
    config: PolicyConfig | None = None,
    document_id: int | None = None,
    today: dt.date | None = None,
    dayfirst: bool = False,
) -> AuditResult:
    """Run one document through triage, extraction and policy, start to finish.

    `toolbox` defaults to the real models and the no-op history lookup (see
    `verity.agent.tools.default_toolbox`); pass a toolbox built with fake
    callables to run this against fixed inputs in a test, or with
    `verity.agent.history.db_history(...)` to compare against a real ledger.
    """
    path = Path(path)
    tools = toolbox or default_toolbox()
    config = config or PolicyConfig()
    trace = Trace(document_id=document_id)

    with trace.step("triage", {"path": str(path)}) as step:
        triage = tools.triage(path)
        step.result = _triage_step_result(triage)
        step.note = triage.reason or "accepted"

    ingestion_status = triage.status
    reject_reason = triage.reason
    fields = ExtractedFields()
    history: list = []

    if triage.status == ACCEPTED:
        try:
            with trace.step("load_image", {"path": str(path)}) as step:
                image = tools.load_image(path)
                step.result = {"size": list(image.size)}
        except PageLoadError as exc:
            # Documented failure mode: triage accepted the file, but no page
            # image could be produced from it. Audited the same way a bad
            # file is -- P-014, never scored -- rather than left half-read.
            ingestion_status = REJECTED
            reject_reason = str(exc)
        else:
            with trace.step("read_fields", {"dayfirst": dayfirst}) as step:
                fields = tools.read_fields(image, dayfirst=dayfirst)
                step.result = fields.as_dict()
                step.note = f"confidence={fields.confidence:.2f}"

            if tools.signature_detection_enabled:
                with trace.step("detect_signature") as step:
                    present, score = tools.detect_signature(image)
                    fields.signature_present = present
                    step.result = {"present": present, "score": round(score, 4)}

            with trace.step("history", {"vendor": fields.vendor}) as step:
                history = list(tools.history(fields))
                step.result = {"count": len(history)}

    ctx = AuditContext(
        fields=fields,
        config=config,
        document_id=document_id,
        filename=path.name,
        ingestion_status=ingestion_status,
        reject_reason=reject_reason,
        history=history,
        today=today or dt.date.today(),
    )

    with trace.step("evaluate", note="deterministic; no model or I/O in this step") as step:
        findings = rules.evaluate(ctx)
        verdict = rules.verdict(findings)
        step.result = {"verdict": verdict, "finding_count": len(findings)}
        step.note = ", ".join(f.rule_id for f in findings) or "no findings"

    trace.finish()

    return AuditResult(
        filename=path.name,
        verdict=verdict,
        findings=findings,
        fields=fields,
        config=config,
        ingestion_status=ingestion_status,
        reject_reason=reject_reason,
        trace=trace,
        document_id=document_id,
    )
