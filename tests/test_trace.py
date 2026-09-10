"""The audit trail's own correctness. If a step's ok/error/duration lies, every
downstream claim the trace makes -- "nothing here was silently skipped" -- is
false, and that claim is the entire point of the module."""

from __future__ import annotations

import json
import time

import pytest

from verity.obs.trace import Trace


def test_step_records_success():
    trace = Trace(document_id=7)
    with trace.step("triage", {"path": "a.png"}, note="looks fine") as step:
        step.result = {"status": "accepted"}

    assert len(trace.steps) == 1
    recorded = trace.steps[0]
    assert recorded.index == 1
    assert recorded.tool == "triage"
    assert recorded.args == {"path": "a.png"}
    assert recorded.result == {"status": "accepted"}
    assert recorded.ok is True
    assert recorded.error is None
    assert recorded.note == "looks fine"
    assert recorded.duration_ms >= 0


def test_step_marks_failure_and_reraises():
    trace = Trace()
    with pytest.raises(ValueError, match="boom"), trace.step("read_fields"):
        raise ValueError("boom")

    step = trace.steps[0]
    assert step.ok is False
    assert step.error == "ValueError: boom"


def test_step_record_exists_even_when_the_body_raises():
    """The record is appended before the body runs, so a failing call still
    shows up in the trace -- an audit cannot quietly drop a step it ran."""
    trace = Trace()
    try:
        with trace.step("detect_signature"):
            assert len(trace.steps) == 1
            raise RuntimeError("model down")
    except RuntimeError:
        pass
    assert len(trace.steps) == 1
    assert trace.steps[0].tool == "detect_signature"


def test_indices_increment_across_steps():
    trace = Trace()
    with trace.step("a"):
        pass
    with trace.step("b"):
        pass
    assert [s.index for s in trace.steps] == [1, 2]


def test_failed_steps_property_only_lists_failures():
    trace = Trace()
    with trace.step("ok_step"):
        pass
    with pytest.raises(RuntimeError), trace.step("bad_step"):
        raise RuntimeError("nope")
    assert [s.tool for s in trace.failed_steps] == ["bad_step"]


def test_duration_ms_before_finish_keeps_advancing():
    trace = Trace()
    first = trace.duration_ms
    time.sleep(0.01)
    assert trace.duration_ms > first
    assert trace.finished_at is None


def test_finish_freezes_duration():
    trace = Trace()
    trace.finish()
    assert trace.finished_at is not None
    frozen = trace.duration_ms
    time.sleep(0.01)
    assert trace.duration_ms == frozen


def test_as_dict_and_to_json_round_trip():
    trace = Trace(document_id=3, run_id="fixed-id")
    with trace.step("triage", {"path": "x"}, note="ok") as step:
        step.result = {"status": "accepted"}
    trace.finish()

    data = trace.as_dict()
    assert data["run_id"] == "fixed-id"
    assert data["document_id"] == 3
    assert data["finished_at"] is not None
    assert len(data["steps"]) == 1

    assert json.loads(trace.to_json()) == data


def test_run_id_is_generated_when_not_given():
    a, b = Trace(), Trace()
    assert a.run_id != b.run_id
    assert len(a.run_id) == 32  # uuid4 hex


def test_jsonable_falls_back_to_repr_for_unknown_objects():
    class Unserializable:
        def __repr__(self):
            return "<weird>"

    trace = Trace()
    with trace.step("weird") as step:
        step.result = Unserializable()

    assert trace.as_dict()["steps"][0]["result"] == "<weird>"


def test_jsonable_uses_as_dict_when_available():
    class HasAsDict:
        def as_dict(self):
            return {"a": 1}

    trace = Trace()
    with trace.step("has_as_dict") as step:
        step.result = HasAsDict()

    assert trace.as_dict()["steps"][0]["result"] == {"a": 1}


def test_jsonable_handles_dates_and_nested_collections():
    import datetime as dt

    trace = Trace()
    with trace.step("nested") as step:
        step.result = {"when": dt.date(2026, 1, 1), "items": [1, (2, 3), {4, 5}]}

    result = trace.as_dict()["steps"][0]["result"]
    assert result["when"] == "2026-01-01"
    assert sorted(result["items"][2]) == [4, 5]
