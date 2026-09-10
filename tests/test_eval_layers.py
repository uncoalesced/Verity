"""Trajectory scoring, retrieval scoring, and the trace export.

The common thread: each of these is a measurement, and a measurement that
flatters itself is worse than no measurement. So most of what is checked here is
the refusal cases -- calibration refusing a report that has no model confidence
in it, retrieval scoring counting a miss as a miss, the exporter refusing to
pretend it shipped something.
"""

from __future__ import annotations

import json

import pytest

from verity.eval import rag_eval, trajectory_eval
from verity.eval.fraud_cases import CORPUS_DIR, build_cases
from verity.obs import langfuse_export
from verity.obs.cost import usage_for
from verity.obs.trace import Trace

M500 = CORPUS_DIR / "verity_sample_invoices_m_500.csv"


# --- trajectory ------------------------------------------------------------


def test_expected_route_is_written_from_the_policy_not_the_graph():
    """A rejected document reads nothing, so nothing downstream may comment."""
    assert trajectory_eval.expected_route(
        intake_accepted=False, page_loaded=False, signature_enabled=True
    ) == ["triage", "evaluate"]


def test_expected_route_stops_one_step_later_when_the_page_will_not_load():
    assert trajectory_eval.expected_route(
        intake_accepted=True, page_loaded=False, signature_enabled=True
    ) == ["triage", "load_image", "evaluate"]


def test_expected_route_omits_signature_detection_when_it_is_off():
    route = trajectory_eval.expected_route(
        intake_accepted=True, page_loaded=True, signature_enabled=False
    )
    assert "detect_signature" not in route
    assert route == ["triage", "load_image", "read_fields", "history", "evaluate"]


def test_the_citation_node_is_always_last():
    route = trajectory_eval.expected_route(
        intake_accepted=True, page_loaded=True, signature_enabled=True, check_citations=True
    )
    assert route[-1] == "check_citations"
    assert route.index("evaluate") < route.index("check_citations")


def test_every_shipped_scenario_routes_correctly(tmp_path):
    report = trajectory_eval.evaluate_trajectories(trajectory_eval.default_scenarios(tmp_path))
    assert report.scenarios == 5
    assert report.success_rate == 1.0, [o.name for o in report.outcomes if not o.ok]


def test_a_wrong_route_is_scored_as_a_failure(tmp_path):
    """The metric has to be able to fail, or it is not a metric."""
    scenarios = trajectory_eval.default_scenarios(tmp_path)
    scenarios[0].expected = ["triage", "evaluate"]  # not what a readable page does
    report = trajectory_eval.evaluate_trajectories(scenarios[:1])
    assert report.success_rate == 0.0
    assert report.outcomes[0].ok is False


# --- calibration -----------------------------------------------------------


def test_calibration_buckets_by_confidence_and_measures_being_right():
    outcomes = [
        {"confidence": 0.95, "missed": [], "spurious": []},
        {"confidence": 0.91, "missed": [], "spurious": []},
        {"confidence": 0.35, "missed": ["P-002"], "spurious": []},
        {"confidence": 0.25, "missed": [], "spurious": ["P-010"]},
    ]
    result = trajectory_eval.calibrate(outcomes, bins=5)
    assert result["documents"] == 4
    top = next(b for b in result["buckets"] if b["range"] == [0.8, 1.0])
    assert top["documents"] == 2
    assert top["accuracy"] == 1.0
    low = next(b for b in result["buckets"] if b["range"] == [0.2, 0.4])
    assert low["accuracy"] == 0.0


def test_a_half_right_document_is_not_half_correct():
    """An approver acting on the wrong finding acted wrongly. No partial credit."""
    result = trajectory_eval.calibrate([{"confidence": 0.9, "missed": [], "spurious": ["P-010"]}])
    assert result["buckets"][0]["correct"] == 0


def test_a_perfectly_calibrated_set_has_no_error():
    outcomes = [{"confidence": 1.0, "missed": [], "spurious": []} for _ in range(4)]
    assert trajectory_eval.calibrate(outcomes)["expected_calibration_error"] == 0.0


def test_overconfidence_shows_up_as_a_positive_gap():
    outcomes = [{"confidence": 0.9, "missed": ["P-002"], "spurious": []} for _ in range(4)]
    result = trajectory_eval.calibrate(outcomes)
    assert result["expected_calibration_error"] == pytest.approx(0.9)
    assert result["buckets"][0]["gap"] == pytest.approx(0.9)


def test_calibration_refuses_a_report_with_no_model_confidence_in_it(tmp_path):
    """The CSV confidence column is a label, not a reading. Bucketing it would
    draw a calibration curve for something that never made a prediction."""
    path = tmp_path / "fields_report.json"
    path.write_text(json.dumps({"source": "fields", "outcomes": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="--source images"):
        trajectory_eval.calibration_from_report(path)


def test_calibration_accepts_a_report_read_from_images(tmp_path):
    path = tmp_path / "image_report.json"
    path.write_text(
        json.dumps(
            {"source": "images", "outcomes": [{"confidence": 0.8, "missed": [], "spurious": []}]}
        ),
        encoding="utf-8",
    )
    assert trajectory_eval.calibration_from_report(path)["documents"] == 1


# --- retrieval -------------------------------------------------------------


def test_notes_queries_are_independent_of_the_finding_wording():
    """The whole point of the default query source: the words come from the
    corpus, not from the policy the search is supposed to find."""
    samples = rag_eval.build_samples(build_cases(path=M500)[:200], queries=rag_eval.NOTES)
    assert samples
    for sample in samples:
        assert sample.query
        assert sample.query != sample.expected_policy_text


def test_finding_queries_score_higher_than_notes_queries():
    """Documented as a tautology in the module, asserted here so nobody quotes
    the easy number as if it were the hard one."""
    cases = build_cases(path=M500)[:200]
    notes = rag_eval.retrieval_hits(rag_eval.build_samples(cases, queries=rag_eval.NOTES))
    finding = rag_eval.retrieval_hits(rag_eval.build_samples(cases, queries=rag_eval.FINDING))
    assert finding["hit_at_1"] > notes["hit_at_1"]


def test_a_policy_that_never_comes_back_is_named():
    sample = rag_eval.Sample(
        document="d",
        query="q",
        expected_policy_id="P-011",
        expected_policy_text="t",
        retrieved_ids=["P-009", "P-002"],
        retrieved_texts=["a", "b"],
    )
    assert sample.rank is None
    result = rag_eval.retrieval_hits([sample])
    assert result["hit_at_1"] == 0.0
    assert result["never_retrieved"] == ["P-011"]


def test_reciprocal_rank_rewards_a_higher_position():
    first = rag_eval.Sample("d", "q", "P-002", "t", ["P-002", "P-009"], ["a", "b"])
    second = rag_eval.Sample("d", "q", "P-002", "t", ["P-009", "P-002"], ["a", "b"])
    assert rag_eval.retrieval_hits([first])["mrr"] == 1.0
    assert rag_eval.retrieval_hits([second])["mrr"] == 0.5


def test_an_unknown_query_source_is_rejected():
    with pytest.raises(ValueError, match="queries must be one of"):
        rag_eval.build_samples([], queries="vibes")


def test_ragas_refuses_to_report_zero_when_it_cannot_run(monkeypatch):
    """A score of 0.0 and 'we could not measure it' are opposite findings."""
    monkeypatch.setattr(rag_eval, "available", lambda: False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        rag_eval.evaluate_ragas([])


# --- the trace export ------------------------------------------------------


def _trace() -> Trace:
    trace = Trace(document_id=7)
    with trace.step("triage", {"path": "a.png"}) as step:
        step.result = {"status": "accepted"}
        step.note = "accepted"
    try:
        with trace.step("read_fields"):
            raise RuntimeError("model server down")
    except RuntimeError:
        pass
    return trace.finish()


def test_the_payload_carries_one_span_per_step():
    payload = langfuse_export.trace_payload(_trace(), verdict="review", filename="a.png")
    assert [s["name"] for s in payload["spans"]] == ["triage", "read_fields"]
    assert payload["session_id"]
    assert payload["metadata"]["verdict"] == "review"


def test_a_failed_step_is_exported_as_an_error_not_a_success():
    payload = langfuse_export.trace_payload(_trace())
    failed = payload["spans"][1]
    assert failed["level"] == "ERROR"
    assert "model server down" in failed["status_message"]
    assert payload["metadata"]["failed_steps"] == ["read_fields"]


def test_llm_cost_rides_along_when_there_was_any():
    payload = langfuse_export.trace_payload(_trace(), usage=usage_for("claude-opus-5", 1000, 50))
    assert payload["metadata"]["llm"]["calls"] == 1
    assert float(payload["metadata"]["llm"]["cost_usd"]) > 0


def test_no_cost_block_when_no_model_was_called():
    payload = langfuse_export.trace_payload(_trace())
    assert "llm" not in payload["metadata"]


def test_export_reports_false_rather_than_pretending_when_unconfigured(monkeypatch):
    for name in langfuse_export.REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)
    assert langfuse_export.enabled() is False
    assert langfuse_export.export_trace(_trace()) is False


def test_a_broken_backend_does_not_fail_the_audit(monkeypatch):
    """The trace is a diagnostic copy. Losing it must never lose the audit."""
    monkeypatch.setattr(langfuse_export, "enabled", lambda: True)

    def boom():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(langfuse_export, "_client", boom)
    assert langfuse_export.export_trace(_trace()) is False
