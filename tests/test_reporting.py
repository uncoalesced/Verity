"""The exception report and the audit pack."""

import csv
import io

from conftest import clean_reading, fake_toolbox

from verity.agent.loop import run_audit
from verity.db import persist
from verity.db.models import ReviewDecision
from verity.policy.library import PolicyConfig
from verity.reporting import exceptions as reporting


def stored_run(session, receipt_png, fields=None, config=None):
    config = config or PolicyConfig()
    result = run_audit(receipt_png, toolbox=fake_toolbox(fields), config=config)
    run = persist.save_audit(session, result, config=config)
    session.commit()
    return persist.load_run(session, run.run_id)


def test_clean_documents_stay_out_of_the_exception_report(session, receipt_png):
    stored_run(session, receipt_png)
    stored_run(session, receipt_png, clean_reading(vendor=None))

    rows = reporting.exception_rows(persist.recent_runs(session))
    assert len(rows) == 1
    assert "P-003" in rows[0]["rule_ids"]


def test_full_population_can_be_pulled_for_a_sample(session, receipt_png):
    stored_run(session, receipt_png)
    stored_run(session, receipt_png, clean_reading(vendor=None))

    rows = reporting.exception_rows(persist.recent_runs(session), held_only=False)
    assert len(rows) == 2


def test_a_comma_in_a_supplier_name_does_not_shift_the_columns(session, receipt_png):
    stored_run(session, receipt_png, clean_reading(vendor="Smith, Jones & Co", date=None))

    text = reporting.to_csv(persist.recent_runs(session))
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]["vendor"] == "Smith, Jones & Co"
    assert rows[0]["verdict"] == "review"


def test_the_audit_pack_carries_the_policy_wording_and_the_trace(session, receipt_png):
    run = stored_run(session, receipt_png, clean_reading(vendor=None))
    pack = reporting.audit_pack(run)

    assert pack["findings"][0]["policy_text"]
    assert pack["thresholds_in_force"]["approval_limit"]
    assert pack["trace"]
    assert pack["review"] is None


def test_an_override_is_visible_in_the_summary(session, receipt_png):
    run = stored_run(session, receipt_png, clean_reading(total=None))
    assert run.verdict == "blocked"

    session.add(
        ReviewDecision(
            audit_run_id=run.id,
            decision="approved",
            reviewer="A. Controller",
            rationale="Original receipt produced separately.",
            overrides_verdict=True,
        )
    )
    session.commit()
    # The run is already in this session's identity map with an empty review
    # collection; a real request would use a fresh session.
    session.expire_all()

    summary = reporting.summarise(persist.recent_runs(session))
    assert summary["reviewer_overrides"] == 1
    assert summary["by_verdict"]["blocked"] == 1


def test_summary_ranks_the_controls_that_fire_most(session, receipt_png):
    for _ in range(3):
        stored_run(session, receipt_png, clean_reading(vendor=None))
    stored_run(session, receipt_png, clean_reading(date=None))

    summary = reporting.summarise(persist.recent_runs(session))
    assert next(iter(summary["by_rule"])) == "P-003"
    assert summary["by_rule"]["P-003"] == 3


def test_saved_and_unsaved_reports_use_the_same_columns(session, receipt_png):
    """A dry run and a stored run must describe the same document identically.

    This is the whole reason `results_to_csv` exists rather than the batch
    script formatting its own CSV.
    """
    fields = clean_reading(vendor=None)
    result = run_audit(receipt_png, toolbox=fake_toolbox(fields), config=PolicyConfig())
    persist.save_audit(session, result, config=PolicyConfig())
    session.commit()

    from_memory = list(csv.DictReader(io.StringIO(reporting.results_to_csv([result]))))
    from_db = list(csv.DictReader(io.StringIO(reporting.to_csv(persist.recent_runs(session)))))

    assert from_memory[0].keys() == from_db[0].keys()
    for column in ("run_id", "filename", "verdict", "worst_severity", "rule_ids", "vendor"):
        assert from_memory[0][column] == from_db[0][column], column


def test_an_unsaved_clean_run_stays_out_of_the_dry_run_report(receipt_png):
    result = run_audit(receipt_png, toolbox=fake_toolbox(), config=PolicyConfig())
    rows = list(csv.DictReader(io.StringIO(reporting.results_to_csv([result]))))
    assert rows == []
