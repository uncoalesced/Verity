"""The same audit, expressed as a graph.

`loop.py` runs the audit as a straight-line function. This runs it as a
LangGraph state machine over the identical steps, calling the identical tools
and the identical rules, and returns the identical verdict. There is a parity
test (`tests/test_graph.py`) that asserts exactly that on every branch, because
a second execution path that quietly disagrees with the first is worse than not
having one.

Why bother, then. Two things the graph gives that the function does not:

* **The route is data.** Which nodes ran, in what order, is a value on the
  result rather than something you infer by reading the code. That is what
  `verity.eval.trajectory_eval` scores: did this document take the path its
  shape required -- skip extraction when intake rejected it, skip signature
  detection when it is switched off, stop before history when no page could be
  loaded.
* **The citation check has somewhere to live.** It is a node after `evaluate`,
  conditional on being configured, which is the honest shape: an optional step
  that reads the findings and writes a note, and cannot reach back and change
  them.

What the graph deliberately does **not** do is let the model choose the route.
Every branch here is a deterministic function of the document's state. An agent
that decides which controls to run on a payment is an agent that can decide not
to run one, and the whole point of `rules.py` is that every control runs on
every document.

ponytail: the graph mirrors the loop rather than replacing it. `loop.run_audit`
stays the default path -- fewer moving parts for the API and the batch script,
which do not need the route as data.
"""

from __future__ import annotations

import datetime as dt
import logging
import operator
from pathlib import Path
from typing import Annotated, Any, TypedDict

from verity.agent.loop import AuditResult, _triage_step_result
from verity.agent.tools import PageLoadError, Toolbox, default_toolbox
from verity.extraction.schema import ExtractedFields
from verity.ingestion.router import ACCEPTED, REJECTED
from verity.obs.trace import Trace
from verity.policy import rules
from verity.policy.library import PolicyConfig
from verity.policy.rules import AuditContext

log = logging.getLogger(__name__)

TRIAGE = "triage"
LOAD_IMAGE = "load_image"
READ_FIELDS = "read_fields"
DETECT_SIGNATURE = "detect_signature"
HISTORY = "history"
EVALUATE = "evaluate"
CHECK_CITATIONS = "check_citations"

# Every node the graph can visit, in the order a fully exercised document would
# hit them. `trajectory_eval` uses this to say what "in order" means.
NODES = (TRIAGE, LOAD_IMAGE, READ_FIELDS, DETECT_SIGNATURE, HISTORY, EVALUATE, CHECK_CITATIONS)


class AuditState(TypedDict, total=False):
    """What flows between nodes.

    `visited` accumulates rather than being overwritten -- it is the trajectory,
    and a node that forgot to append itself would be a node that silently did
    not run as far as any downstream metric is concerned.
    """

    path: str
    toolbox: Toolbox
    config: PolicyConfig
    document_id: int | None
    today: dt.date
    dayfirst: bool
    check_citations: bool
    trace: Trace
    image: Any
    fields: ExtractedFields
    history: list
    ingestion_status: str
    reject_reason: str | None
    findings: list
    verdict: str
    citations: Any
    visited: Annotated[list[str], operator.add]


def _node_triage(state: AuditState) -> dict:
    trace, tools, path = state["trace"], state["toolbox"], Path(state["path"])
    with trace.step(TRIAGE, {"path": str(path)}) as step:
        triage = tools.triage(path)
        step.result = _triage_step_result(triage)
        step.note = triage.reason or "accepted"
    return {
        "ingestion_status": triage.status,
        "reject_reason": triage.reason,
        "visited": [TRIAGE],
    }


def _node_load_image(state: AuditState) -> dict:
    trace, tools, path = state["trace"], state["toolbox"], Path(state["path"])
    try:
        with trace.step(LOAD_IMAGE, {"path": str(path)}) as step:
            image = tools.load_image(path)
            step.result = {"size": list(image.size)}
    except PageLoadError as exc:
        # Documented failure mode, handled exactly as the loop handles it: the
        # document becomes a P-014 rejection rather than a half-read audit.
        return {
            "ingestion_status": REJECTED,
            "reject_reason": str(exc),
            "visited": [LOAD_IMAGE],
        }
    return {"image": image, "visited": [LOAD_IMAGE]}


def _node_read_fields(state: AuditState) -> dict:
    trace, tools = state["trace"], state["toolbox"]
    with trace.step(READ_FIELDS, {"dayfirst": state["dayfirst"]}) as step:
        fields = tools.read_fields(state["image"], dayfirst=state["dayfirst"])
        step.result = fields.as_dict()
        step.note = f"confidence={fields.confidence:.2f}"
    return {"fields": fields, "visited": [READ_FIELDS]}


def _node_detect_signature(state: AuditState) -> dict:
    trace, tools, fields = state["trace"], state["toolbox"], state["fields"]
    with trace.step(DETECT_SIGNATURE) as step:
        present, score = tools.detect_signature(state["image"])
        fields.signature_present = present
        step.result = {"present": present, "score": round(score, 4)}
    return {"fields": fields, "visited": [DETECT_SIGNATURE]}


def _node_history(state: AuditState) -> dict:
    trace, tools, fields = state["trace"], state["toolbox"], state["fields"]
    with trace.step(HISTORY, {"vendor": fields.vendor}) as step:
        history = list(tools.history(fields))
        step.result = {"count": len(history)}
    return {"history": history, "visited": [HISTORY]}


def _node_evaluate(state: AuditState) -> dict:
    trace = state["trace"]
    ctx = AuditContext(
        fields=state.get("fields") or ExtractedFields(),
        config=state["config"],
        document_id=state.get("document_id"),
        filename=Path(state["path"]).name,
        ingestion_status=state.get("ingestion_status", ACCEPTED),
        reject_reason=state.get("reject_reason"),
        history=state.get("history") or [],
        today=state["today"],
    )
    with trace.step(EVALUATE, note="deterministic; no model or I/O in this step") as step:
        findings = rules.evaluate(ctx)
        verdict = rules.verdict(findings)
        step.result = {"verdict": verdict, "finding_count": len(findings)}
        step.note = ", ".join(f.rule_id for f in findings) or "no findings"
    return {"findings": findings, "verdict": verdict, "visited": [EVALUATE]}


def _node_check_citations(state: AuditState) -> dict:
    """Ask Claude whether each finding's quoted policy supports it.

    Imported here rather than at module scope so the graph can be built and run
    with no LLM configured and no SDK import cost.
    """
    from verity.llm.citation_check import check_findings

    trace = state["trace"]
    with trace.step(CHECK_CITATIONS, {"findings": len(state["findings"])}) as step:
        report = check_findings(state["findings"])
        step.result = report.as_dict()
        unsupported = [c.rule_id for c in report.unsupported]
        step.note = (
            f"unsupported citation on {', '.join(unsupported)}"
            if unsupported
            else f"{report.ran} citation(s) checked"
        )
    return {"citations": report, "visited": [CHECK_CITATIONS]}


# --- routing ---------------------------------------------------------------
# Every one of these is a pure function of the document's state. None of them
# consults a model.


def _after_triage(state: AuditState) -> str:
    return LOAD_IMAGE if state["ingestion_status"] == ACCEPTED else EVALUATE


def _after_load_image(state: AuditState) -> str:
    return EVALUATE if state["ingestion_status"] == REJECTED else READ_FIELDS


def _after_read_fields(state: AuditState) -> str:
    return DETECT_SIGNATURE if state["toolbox"].signature_detection_enabled else HISTORY


def _after_evaluate(state: AuditState) -> str:
    from langgraph.graph import END

    return CHECK_CITATIONS if state.get("check_citations") else END


def build_graph():
    """Compile the audit graph. Structure only -- no tools bound yet."""
    from langgraph.graph import END, START, StateGraph

    builder = StateGraph(AuditState)
    builder.add_node(TRIAGE, _node_triage)
    builder.add_node(LOAD_IMAGE, _node_load_image)
    builder.add_node(READ_FIELDS, _node_read_fields)
    builder.add_node(DETECT_SIGNATURE, _node_detect_signature)
    builder.add_node(HISTORY, _node_history)
    builder.add_node(EVALUATE, _node_evaluate)
    builder.add_node(CHECK_CITATIONS, _node_check_citations)

    builder.add_edge(START, TRIAGE)
    builder.add_conditional_edges(TRIAGE, _after_triage, {LOAD_IMAGE: LOAD_IMAGE, EVALUATE: EVALUATE})
    builder.add_conditional_edges(
        LOAD_IMAGE, _after_load_image, {READ_FIELDS: READ_FIELDS, EVALUATE: EVALUATE}
    )
    builder.add_conditional_edges(
        READ_FIELDS, _after_read_fields, {DETECT_SIGNATURE: DETECT_SIGNATURE, HISTORY: HISTORY}
    )
    builder.add_edge(DETECT_SIGNATURE, HISTORY)
    builder.add_edge(HISTORY, EVALUATE)
    builder.add_conditional_edges(EVALUATE, _after_evaluate, {CHECK_CITATIONS: CHECK_CITATIONS, END: END})
    builder.add_edge(CHECK_CITATIONS, END)
    return builder.compile()


class GraphAuditResult(AuditResult):
    """An `AuditResult` that also knows which nodes it visited.

    Subclassed rather than replaced so everything downstream -- persistence, the
    API, the exception report -- keeps working on a graph run without knowing
    the graph exists.
    """

    def __init__(self, *, visited: list[str], citations=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.visited = visited
        self.citations = citations

    def as_dict(self) -> dict:
        data = super().as_dict()
        data["visited"] = list(self.visited)
        data["citations"] = self.citations.as_dict() if self.citations else None
        return data


def run_audit_graph(
    path: str | Path,
    *,
    toolbox: Toolbox | None = None,
    config: PolicyConfig | None = None,
    document_id: int | None = None,
    today: dt.date | None = None,
    dayfirst: bool = False,
    check_citations: bool = False,
) -> GraphAuditResult:
    """Run one document through the graph. Same answer as `loop.run_audit`.

    `check_citations` adds the optional model step after the controls have run.
    It cannot change the verdict; see `verity.llm.citation_check`.
    """
    path = Path(path)
    trace = Trace(document_id=document_id)
    state: AuditState = {
        "path": str(path),
        "toolbox": toolbox or default_toolbox(),
        "config": config or PolicyConfig(),
        "document_id": document_id,
        "today": today or dt.date.today(),
        "dayfirst": dayfirst,
        "check_citations": check_citations,
        "trace": trace,
        "fields": ExtractedFields(),
        "history": [],
        "ingestion_status": ACCEPTED,
        "reject_reason": None,
        "visited": [],
    }

    final = build_graph().invoke(state)
    trace.finish()

    return GraphAuditResult(
        filename=path.name,
        verdict=final["verdict"],
        findings=final["findings"],
        fields=final.get("fields") or ExtractedFields(),
        config=state["config"],
        ingestion_status=final.get("ingestion_status", ACCEPTED),
        reject_reason=final.get("reject_reason"),
        trace=trace,
        document_id=document_id,
        visited=final.get("visited", []),
        citations=final.get("citations"),
    )
