"""The orchestrator. Exercised entirely against a fake `Toolbox` -- no models,
no database -- so what's under test is the wiring: step order, how a
rejection short-circuits the pipeline, and the one documented failure mode
(`PageLoadError`) that turns into a rejection instead of a crash."""

from __future__ import annotations

import datetime as dt
from decimal import Decimal
from pathlib import Path

import pytest
from PIL import Image

from verity.agent.loop import run_audit
from verity.agent.tools import PageLoadError, Toolbox
from verity.extraction.schema import ExtractedFields
from verity.ingestion.router import ACCEPTED, REJECTED, TriageResult
from verity.policy import rules

TODAY = dt.date(2026, 6, 1)


def accepted_triage(path):
    return TriageResult(path=Path(path), status=ACCEPTED, format="image")


def rejected_triage(reason):
    def triage(path):
        return TriageResult(path=Path(path), status=REJECTED, format=None, reason=reason)

    return triage


def clean_fields():
    return ExtractedFields(
        vendor="Acme Ltd.",
        date=TODAY,
        total=Decimal("42.00"),
        subtotal=Decimal("42.00"),
        confidence=0.95,
    )


def fake_toolbox(**overrides):
    kwargs = {
        "triage": accepted_triage,
        "load_image": lambda path: Image.new("RGB", (10, 10)),
        "read_fields": lambda image, dayfirst=False: clean_fields(),
        "read_field": lambda image, field_name, question=None: "",
        "detect_signature": lambda image: (True, 0.9),
        "history": lambda fields: [],
        "signature_detection_enabled": True,
    }
    kwargs.update(overrides)
    return Toolbox(**kwargs)


def test_clean_document_passes(tmp_path):
    path = tmp_path / "receipt.png"
    path.write_bytes(b"stand-in bytes; triage is faked below")

    result = run_audit(path, toolbox=fake_toolbox(), document_id=1, today=TODAY)

    assert result.verdict == rules.PASS
    assert result.findings == []
    assert result.ingestion_status == ACCEPTED
    assert result.ok is True
    assert result.document_id == 1
    assert [s.tool for s in result.trace.steps] == [
        "triage",
        "load_image",
        "read_fields",
        "detect_signature",
        "history",
        "evaluate",
    ]
    assert all(s.ok for s in result.trace.steps)


def test_triage_rejection_short_circuits_before_any_model_call(tmp_path):
    path = tmp_path / "bad.png"
    path.write_bytes(b"garbage")
    calls: list[str] = []

    toolbox = fake_toolbox(
        triage=rejected_triage("corrupt image: OSError"),
        load_image=lambda path: calls.append("load_image") or Image.new("RGB", (1, 1)),
        read_fields=lambda image, dayfirst=False: calls.append("read_fields") or clean_fields(),
    )

    result = run_audit(path, toolbox=toolbox)

    assert calls == []  # nothing past triage ran
    assert result.ingestion_status == REJECTED
    assert result.reject_reason == "corrupt image: OSError"
    assert [f.rule_id for f in result.findings] == ["P-014"]
    assert result.verdict == rules.BLOCKED
    assert [s.tool for s in result.trace.steps] == ["triage", "evaluate"]


def test_page_load_error_is_folded_into_a_rejection_not_raised(tmp_path):
    path = tmp_path / "born_digital.pdf"
    path.write_bytes(b"stand-in bytes; load_image is faked below")

    def failing_load(path):
        raise PageLoadError(f"{path.name}: PDF carries no embedded page image (born-digital)")

    toolbox = fake_toolbox(load_image=failing_load)

    result = run_audit(path, toolbox=toolbox)

    assert result.ingestion_status == REJECTED
    assert "no embedded page image" in result.reject_reason
    assert [f.rule_id for f in result.findings] == ["P-014"]
    assert result.verdict == rules.BLOCKED
    # The failed load_image step is honestly recorded even though the run
    # completed and returned a normal result instead of raising.
    assert result.ok is False
    load_step = next(s for s in result.trace.steps if s.tool == "load_image")
    assert load_step.ok is False
    assert "PageLoadError" in load_step.error
    assert [s.tool for s in result.trace.steps] == ["triage", "load_image", "evaluate"]


def test_unexpected_extraction_failure_propagates_rather_than_being_hidden(tmp_path):
    """A model crash is not a document problem. Folding it into a rejection
    finding would misattribute an infrastructure failure as a document one, so
    this is not caught -- it surfaces to the caller."""
    path = tmp_path / "receipt.png"
    path.write_bytes(b"garbage")

    def crashing_read(image, dayfirst=False):
        raise RuntimeError("model server unreachable")

    toolbox = fake_toolbox(read_fields=crashing_read)

    with pytest.raises(RuntimeError, match="model server unreachable"):
        run_audit(path, toolbox=toolbox)


def test_signature_detection_can_be_disabled(tmp_path):
    path = tmp_path / "receipt.png"
    path.write_bytes(b"garbage")
    calls: list[str] = []

    toolbox = fake_toolbox(
        detect_signature=lambda image: calls.append("detect_signature") or (True, 0.9),
        signature_detection_enabled=False,
    )

    result = run_audit(path, toolbox=toolbox, today=TODAY)

    assert calls == []
    assert "detect_signature" not in [s.tool for s in result.trace.steps]
    assert result.fields.signature_present is None


def test_history_tool_receives_the_fields_just_read(tmp_path):
    path = tmp_path / "receipt.png"
    path.write_bytes(b"garbage")
    seen: dict = {}

    def spy_history(fields):
        seen["vendor"] = fields.vendor
        seen["total"] = fields.total
        return []

    toolbox = fake_toolbox(history=spy_history)

    result = run_audit(path, toolbox=toolbox, document_id=1, today=TODAY)

    assert seen["vendor"] == "Acme Ltd."
    assert seen["total"] == Decimal("42.00")
    assert result.verdict == rules.PASS


def test_a_planted_duplicate_in_history_is_caught(tmp_path):
    path = tmp_path / "receipt.png"
    path.write_bytes(b"garbage")

    def duplicate_history(fields):
        from verity.policy.rules import PriorDocument

        return [PriorDocument(document_id=99, vendor=fields.vendor, total=fields.total, date=fields.date)]

    toolbox = fake_toolbox(history=duplicate_history)

    result = run_audit(path, toolbox=toolbox, document_id=1, today=TODAY)

    assert any(f.rule_id == "P-002" for f in result.findings)
    assert result.verdict == rules.BLOCKED


def test_findings_and_verdict_reflect_a_flagged_document(tmp_path):
    path = tmp_path / "receipt.png"
    path.write_bytes(b"garbage")

    toolbox = fake_toolbox(read_fields=lambda image, dayfirst=False: ExtractedFields(confidence=0.9))

    result = run_audit(path, toolbox=toolbox)

    assert result.verdict == rules.BLOCKED  # no total read at all -> P-001, high
    assert any(f.rule_id == "P-001" for f in result.findings)


def test_as_dict_is_json_shaped(tmp_path):
    path = tmp_path / "receipt.png"
    path.write_bytes(b"garbage")

    result = run_audit(path, toolbox=fake_toolbox(), today=TODAY)
    data = result.as_dict()

    assert data["verdict"] == rules.PASS
    assert data["findings"] == []
    assert data["fields"]["vendor"] == "Acme Ltd."
    assert data["trace"]["steps"]
