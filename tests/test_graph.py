"""The graph must agree with the loop, on every branch.

A second execution path is only worth having if it produces the same answer as
the first. These tests take each branch the graph can route down -- clean
document, rejected intake, unreadable page, signature detection off -- and
assert the graph and the loop reach the identical verdict and the identical set
of findings. Everything else here is about the route itself, which is the thing
the graph adds and the loop cannot report.
"""

from __future__ import annotations

import datetime as dt
from decimal import Decimal

import pytest
from conftest import clean_reading, fake_toolbox
from PIL import Image

from verity.agent import graph
from verity.agent.loop import run_audit
from verity.agent.tools import PageLoadError
from verity.extraction.schema import ExtractedFields
from verity.ingestion import router

TODAY = dt.date(2026, 6, 30)


def _blank_page(tmp_path):
    """A page with no ink on it -- intake rejects this."""
    path = tmp_path / "blank.png"
    Image.new("RGB", (80, 80), "white").save(path)
    return path


def _both(path, toolbox, **kwargs):
    """Run the same document through the loop and the graph."""
    looped = run_audit(path, toolbox=toolbox, today=TODAY, **kwargs)
    graphed = graph.run_audit_graph(path, toolbox=toolbox, today=TODAY, **kwargs)
    return looped, graphed


def _same(looped, graphed) -> None:
    assert graphed.verdict == looped.verdict
    assert [f.rule_id for f in graphed.findings] == [f.rule_id for f in looped.findings]
    assert graphed.ingestion_status == looped.ingestion_status
    assert graphed.reject_reason == looped.reject_reason


# --- parity ----------------------------------------------------------------


def test_clean_document_reaches_the_same_answer_both_ways(receipt_png):
    reading = clean_reading(date=TODAY - dt.timedelta(days=5))
    _same(*_both(receipt_png, fake_toolbox(reading)))


def test_document_with_findings_reaches_the_same_answer_both_ways(receipt_png):
    reading = clean_reading(date=TODAY - dt.timedelta(days=5), total=Decimal("18432.75"))
    looped, graphed = _both(receipt_png, fake_toolbox(reading))
    _same(looped, graphed)
    assert "P-009" in {f.rule_id for f in graphed.findings}


def test_rejected_intake_reaches_the_same_answer_both_ways(tmp_path):
    looped, graphed = _both(_blank_page(tmp_path), fake_toolbox())
    _same(looped, graphed)
    assert graphed.ingestion_status == router.REJECTED
    assert [f.rule_id for f in graphed.findings] == ["P-014"]


def test_unreadable_page_reaches_the_same_answer_both_ways(receipt_png):
    def cannot_load(path):
        raise PageLoadError("born-digital PDF carries no page image")

    looped, graphed = _both(receipt_png, fake_toolbox(load_image=cannot_load))
    _same(looped, graphed)
    assert [f.rule_id for f in graphed.findings] == ["P-014"]


def test_signature_detection_off_reaches_the_same_answer_both_ways(receipt_png):
    reading = clean_reading(date=TODAY - dt.timedelta(days=5), signature_present=None)
    toolbox = fake_toolbox(reading, signature_detection_enabled=False)
    _same(*_both(receipt_png, toolbox))


# --- the route -------------------------------------------------------------


def test_a_full_read_visits_every_step_in_order(receipt_png):
    result = graph.run_audit_graph(receipt_png, toolbox=fake_toolbox(), today=TODAY)
    assert result.visited == [
        graph.TRIAGE,
        graph.LOAD_IMAGE,
        graph.READ_FIELDS,
        graph.DETECT_SIGNATURE,
        graph.HISTORY,
        graph.EVALUATE,
    ]


def test_signature_detection_is_skipped_when_it_is_switched_off(receipt_png):
    toolbox = fake_toolbox(signature_detection_enabled=False)
    result = graph.run_audit_graph(receipt_png, toolbox=toolbox, today=TODAY)
    assert graph.DETECT_SIGNATURE not in result.visited
    assert graph.HISTORY in result.visited


def test_a_rejected_document_never_reaches_extraction(tmp_path):
    """Nothing was read, so nothing downstream of intake has anything to say."""
    result = graph.run_audit_graph(_blank_page(tmp_path), toolbox=fake_toolbox(), today=TODAY)
    assert result.visited == [graph.TRIAGE, graph.EVALUATE]


def test_an_unreadable_page_stops_before_extraction(receipt_png):
    def cannot_load(path):
        raise PageLoadError("no embedded page image")

    result = graph.run_audit_graph(receipt_png, toolbox=fake_toolbox(load_image=cannot_load), today=TODAY)
    assert result.visited == [graph.TRIAGE, graph.LOAD_IMAGE, graph.EVALUATE]
    assert graph.READ_FIELDS not in result.visited


def test_the_trace_records_the_same_steps_the_route_reports(receipt_png):
    result = graph.run_audit_graph(receipt_png, toolbox=fake_toolbox(), today=TODAY)
    assert [s.tool for s in result.trace.steps] == result.visited
    assert result.ok


# --- the citation node -----------------------------------------------------


def test_the_citation_node_is_off_unless_asked_for(receipt_png):
    result = graph.run_audit_graph(receipt_png, toolbox=fake_toolbox(), today=TODAY)
    assert graph.CHECK_CITATIONS not in result.visited
    assert result.citations is None


def test_the_citation_node_runs_after_the_controls_and_changes_nothing(receipt_png, monkeypatch):
    """The model gets to comment on the citation. It does not get a vote."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)  # checks report as skipped
    reading = clean_reading(date=TODAY - dt.timedelta(days=5), total=Decimal("18432.75"))

    without = graph.run_audit_graph(receipt_png, toolbox=fake_toolbox(reading), today=TODAY)
    with_check = graph.run_audit_graph(
        receipt_png, toolbox=fake_toolbox(reading), today=TODAY, check_citations=True
    )

    assert with_check.visited[-1] == graph.CHECK_CITATIONS
    assert with_check.verdict == without.verdict
    assert [f.rule_id for f in with_check.findings] == [f.rule_id for f in without.findings]
    assert with_check.citations is not None
    assert with_check.citations.faithfulness is None  # nothing ran; not a pass


def test_the_result_serialises_with_its_route(receipt_png):
    result = graph.run_audit_graph(receipt_png, toolbox=fake_toolbox(), today=TODAY)
    data = result.as_dict()
    assert data["visited"] == result.visited
    assert data["verdict"] == result.verdict
    assert "trace" in data


# --- the shape of the graph itself -----------------------------------------


@pytest.mark.parametrize("node", graph.NODES)
def test_every_declared_node_exists_in_the_compiled_graph(node):
    """`NODES` is what trajectory scoring measures against. If it drifts from
    the graph, the metric silently starts measuring the wrong thing."""
    assert node in graph.build_graph().get_graph().nodes


def test_extracted_fields_default_when_nothing_was_read(tmp_path):
    result = graph.run_audit_graph(_blank_page(tmp_path), toolbox=fake_toolbox(), today=TODAY)
    assert result.fields == ExtractedFields()
