"""A run is saved whole, or the record is worse than useless."""

import datetime as dt
from decimal import Decimal

from conftest import clean_reading, fake_toolbox

from verity.agent.loop import run_audit
from verity.db import persist
from verity.db.models import ReviewDecision
from verity.ingestion.router import route
from verity.policy.library import PolicyConfig


def audit(receipt_png, **kwargs):
    return run_audit(receipt_png, toolbox=fake_toolbox(**kwargs), config=PolicyConfig())


def test_verdict_findings_and_trace_all_land_together(session, receipt_png):
    result = run_audit(
        receipt_png,
        toolbox=fake_toolbox(clean_reading(total=None)),
        config=PolicyConfig(),
    )
    run = persist.save_audit(session, result, config=PolicyConfig())
    session.commit()

    stored = persist.load_run(session, run.run_id)
    assert stored.verdict == result.verdict
    assert [f.rule_id for f in stored.findings] == [f.rule_id for f in result.findings]
    assert len(stored.steps) == len(result.trace.steps)


def test_the_thresholds_in_force_are_stored_with_the_run(session, receipt_png):
    """Raising the approval limit later must not rewrite an old verdict."""
    config = PolicyConfig(approval_limit=Decimal("500.00"))
    result = run_audit(receipt_png, toolbox=fake_toolbox(), config=config)
    run = persist.save_audit(session, result, config=config)
    session.commit()

    assert run.config["approval_limit"] == "500.00"
    assert "P-009" in [f.rule_id for f in run.findings]


def test_policy_wording_is_copied_onto_the_finding(session, receipt_png):
    result = run_audit(receipt_png, toolbox=fake_toolbox(clean_reading(vendor=None)))
    run = persist.save_audit(session, result)
    session.commit()

    finding = next(f for f in run.findings if f.rule_id == "P-003")
    assert "supplier" in finding.policy_text.lower()
    assert finding.policy_title


def test_document_and_extraction_rows_are_written(session, receipt_png):
    triage = route(receipt_png)
    document = persist.record_document(session, receipt_png, triage)
    result = run_audit(receipt_png, toolbox=fake_toolbox(), document_id=document.id)
    extraction = persist.record_extraction(session, document.id, result)
    session.commit()

    assert document.ingestion_status == "accepted"
    assert extraction.vendor == "Northwind Supplies"
    assert extraction.total == Decimal("1240.55")


def test_nothing_is_extracted_for_a_rejected_file(session, tmp_path):
    blank = tmp_path / "blank.png"
    from PIL import Image

    Image.new("RGB", (60, 60), "white").save(blank)

    triage = route(blank)
    document = persist.record_document(session, blank, triage)
    result = run_audit(blank, toolbox=fake_toolbox())
    assert persist.record_extraction(session, document.id, result) is None


def test_latest_review_wins_but_the_earlier_one_survives(session, receipt_png):
    result = run_audit(receipt_png, toolbox=fake_toolbox())
    run = persist.save_audit(session, result)
    session.commit()

    for i, decision in enumerate(("needs_info", "approved")):
        session.add(
            ReviewDecision(
                audit_run_id=run.id,
                decision=decision,
                reviewer="A. Controller",
                decided_at=dt.datetime(2026, 6, 30, 9 + i, tzinfo=dt.timezone.utc),
            )
        )
    session.commit()

    stored = persist.load_run(session, run.run_id)
    assert persist.latest_review(stored).decision == "approved"
    assert len(stored.reviews) == 2


def test_run_as_dict_is_json_shaped(session, receipt_png):
    import json

    result = run_audit(receipt_png, toolbox=fake_toolbox())
    run = persist.save_audit(session, result, config=PolicyConfig())
    session.commit()

    payload = persist.run_as_dict(persist.load_run(session, run.run_id))
    json.dumps(payload)  # raises if anything is not serialisable
    assert payload["run_id"] == run.run_id
    assert payload["review"] is None


def test_save_audit_flushes_but_leaves_the_commit_to_the_caller(session, receipt_png):
    """The caller owns the transaction boundary.

    A document, its extraction and its audit belong in one commit; if this
    function committed on its own there would be no way to write them together.
    """
    result = run_audit(receipt_png, toolbox=fake_toolbox())
    run = persist.save_audit(session, result)

    assert run.id is not None  # flushed, so ids are available
    assert session.in_transaction()
    session.rollback()
    assert persist.load_run(session, result.trace.run_id) is None
