"""The fraud set has to be checkable itself.

A labelled eval set is a claim about ground truth, and a claim about ground
truth that nobody verifies is where a flattering number comes from. These tests
check the labelling machinery, not the score: that the synthesised
counterparties are the ones the labels claim, that the history a case sees is
the history a real lookup would return, and that scoring counts a miss as a miss.
"""

from __future__ import annotations

import datetime as dt
from decimal import Decimal

import pytest

from verity.eval import fraud_cases, fraud_eval
from verity.eval.fraud_cases import (
    FRAUD_TYPE_RULES,
    SCORED_RULES,
    UNCOVERED_FRAUD_TYPES,
    FraudCase,
    Row,
    build_cases,
    build_ledger,
    eval_config,
    history_for,
    load_rows,
)
from verity.extraction.schema import ExtractedFields
from verity.policy.library import PolicyConfig
from verity.policy.rules import PriorDocument

M500 = fraud_cases.CORPUS_DIR / "verity_sample_invoices_m_500.csv"


def _row(**overrides) -> Row:
    base = {
        "invoice_id": "INV-0001",
        "vendor": "Northwind Supplies",
        "invoice_date": dt.date(2026, 3, 1),
        "submitted_date": dt.date(2026, 3, 4),
        "subtotal": Decimal("1000.00"),
        "tax": Decimal("180.00"),
        "total": Decimal("1180.00"),
        "currency": "INR",
        "confidence": 0.95,
        "fraud_type": "none",
        "is_fraudulent": False,
        "notes": "",
    }
    base.update(overrides)
    return Row(**base)


# --- the corpus itself ----------------------------------------------------


def test_corpus_loads_and_every_fraud_type_is_accounted_for():
    """No injected fraud type may be silently unhandled.

    A type that is neither mapped to a control nor listed as uncovered would be
    scored as a clean document, which quietly deflates the miss count.
    """
    rows = load_rows()
    assert rows
    known = set(FRAUD_TYPE_RULES) | set(UNCOVERED_FRAUD_TYPES)
    assert {r.fraud_type for r in rows} <= known


def test_scored_rules_are_exactly_the_mapped_controls():
    assert SCORED_RULES == {"P-002", "P-007", "P-010", "P-011", "P-012"}
    assert "P-009" not in SCORED_RULES  # routing, not detection


def test_approved_vendor_list_excludes_ghost_suppliers():
    rows = load_rows()
    ghosts = {r.vendor for r in rows if r.fraud_type == "ghost_vendor"}
    approved = fraud_cases.approved_vendors(rows)
    assert ghosts
    assert not (ghosts & approved)


# --- the synthesised counterparties ---------------------------------------


def test_duplicate_case_gets_a_prior_matching_on_all_three_fields():
    rows = [_row(invoice_id="INV-DUP", fraud_type="duplicate_invoice", is_fraudulent=True)]
    priors = fraud_cases._synthetic_priors(rows, eval_config(rows))
    assert len(priors) == 1
    prior = priors[0]
    assert (prior.vendor, prior.total, prior.date) == (
        rows[0].vendor,
        rows[0].total,
        rows[0].invoice_date,
    )


def test_split_sibling_lands_inside_the_just_under_the_limit_band():
    config = PolicyConfig()
    floor = config.approval_limit * config.split_proximity
    for index in range(50):
        sibling = fraud_cases._split_sibling_total(index, config.approval_limit, config.split_proximity)
        assert floor <= sibling <= config.approval_limit


def test_split_sibling_is_stable_across_runs():
    """An eval whose fixtures move cannot be compared against yesterday's run."""
    config = PolicyConfig()
    first = fraud_cases._split_sibling_total(7, config.approval_limit, config.split_proximity)
    second = fraud_cases._split_sibling_total(7, config.approval_limit, config.split_proximity)
    assert first == second


def test_synthetic_priors_are_only_made_for_the_two_types_that_need_them():
    rows = [
        _row(invoice_id="A", fraud_type="none"),
        _row(invoice_id="B", fraud_type="altered_total", is_fraudulent=True),
        _row(invoice_id="C", fraud_type="ghost_vendor", is_fraudulent=True),
    ]
    assert fraud_cases._synthetic_priors(rows, eval_config(rows)) == []


# --- the history each case sees -------------------------------------------


def test_history_is_scoped_to_the_supplier_and_the_lookback_window():
    ledger = [
        PriorDocument(document_id=1, vendor="Northwind Supplies", total=Decimal("10"), date=dt.date(2026, 3, 1)),
        PriorDocument(document_id=2, vendor="Contoso Fitout", total=Decimal("10"), date=dt.date(2026, 3, 1)),
        PriorDocument(document_id=3, vendor="Northwind Supplies", total=Decimal("10"), date=dt.date(2020, 1, 1)),
    ]
    got = history_for(99, "northwind supplies.", dt.date(2026, 3, 10), ledger)
    assert [p.document_id for p in got] == [1]


def test_history_never_returns_the_document_itself():
    ledger = [
        PriorDocument(document_id=5, vendor="Northwind Supplies", total=Decimal("10"), date=dt.date(2026, 3, 1)),
    ]
    assert history_for(5, "Northwind Supplies", dt.date(2026, 3, 2), ledger) == []


def test_ledger_holds_every_dated_corpus_row_plus_the_synthetic_ones():
    rows = [
        _row(invoice_id="A"),
        _row(invoice_id="B", fraud_type="duplicate_invoice", is_fraudulent=True),
    ]
    ledger = build_ledger(rows, eval_config(rows))
    assert len(ledger) == 3
    assert sum(1 for p in ledger if p.document_id >= fraud_cases.SYNTHETIC_ID_BASE) == 1


# --- case construction ----------------------------------------------------


def test_case_is_audited_on_its_submission_date_not_today():
    """Anchoring the clock is what keeps a three-year corpus from reading as a
    staleness epidemic that says nothing about the controls."""
    case = build_cases(rows=[_row(submitted_date=dt.date(2024, 5, 5))])[0]
    assert case.today == dt.date(2024, 5, 5)


def test_signature_is_recorded_as_unchecked_not_absent():
    case = build_cases(rows=[_row()])[0]
    assert case.fields.signature_present is None


def test_tax_reaches_the_fields_so_the_arithmetic_control_can_be_exact():
    case = build_cases(rows=[_row()])[0]
    assert case.fields.tax == Decimal("180.00")
    assert case.fields.subtotal == Decimal("1000.00")


@pytest.mark.parametrize(
    "fraud_type,rule",
    [
        ("altered_total", "P-007"),
        ("round_number_amount", "P-010"),
        ("duplicate_invoice", "P-002"),
        ("split_invoice", "P-011"),
        ("ghost_vendor", "P-012"),
    ],
)
def test_each_covered_fraud_type_is_caught_by_its_control(fraud_type, rule):
    """End to end on the real corpus: every document carrying this fraud type
    must trip the control that owns it."""
    cases = [c for c in build_cases(path=M500) if c.fraud_type == fraud_type]
    assert cases, f"no {fraud_type} documents in the corpus"
    for case in cases:
        fired, _ = fraud_eval.run_case(case)
        assert rule in fired, f"{case.name} ({fraud_type}) did not trip {rule}"


def test_clean_documents_do_not_trip_a_detection_control():
    """The control that matters most is the one that stays quiet.

    Routing controls are allowed to fire here -- a large invoice needing
    sign-off is not a false positive -- so only the scored set is checked.
    """
    for case in build_cases(path=M500):
        if case.fraud_type != "none":
            continue
        fired, _ = fraud_eval.run_case(case)
        assert not (fired & SCORED_RULES), f"{case.name} tripped {sorted(fired & SCORED_RULES)}"


# --- scoring --------------------------------------------------------------


def _case(name: str, expected: set[str], **overrides) -> FraudCase:
    base = {
        "name": name,
        "document_id": 1,
        "fields": ExtractedFields(confidence=0.9),
        "expected": frozenset(expected),
        "is_fraudulent": bool(expected),
    }
    base.update(overrides)
    return FraudCase(**base)


def test_scoring_counts_a_miss_as_a_miss():
    report = fraud_eval.score(
        [_case("missed", {"P-002"})], [(set(), "pass")], corpus="x.csv", source="fields"
    )
    assert report.per_rule["P-002"]["recall"] == 0.0
    assert report.detection["caught"] == 0
    assert report.outcomes[0].missed == ["P-002"]


def test_scoring_counts_a_spurious_control_against_precision():
    report = fraud_eval.score(
        [_case("clean", set(), is_fraudulent=False)], [({"P-010"}, "review")], corpus="x.csv", source="fields"
    )
    assert report.per_rule["P-010"]["precision"] == 0.0
    assert report.noise["clean_with_scored_finding"] == 1


def test_routing_controls_do_not_count_as_false_positives():
    """P-009 on a clean document is the approval limit doing its job."""
    report = fraud_eval.score(
        [_case("clean", set(), is_fraudulent=False)], [({"P-009"}, "review")], corpus="x.csv", source="fields"
    )
    assert report.noise["clean_with_scored_finding"] == 0
    assert report.noise["clean_with_any_finding"] == 1
    assert report.micro["fp"] == 0


def test_uncovered_fraud_is_reported_as_a_gap_not_as_a_catch():
    case = _case(
        "po",
        set(),
        fraud_type="mismatched_po",
        is_fraudulent=True,
        uncovered_reason=UNCOVERED_FRAUD_TYPES["mismatched_po"],
    )
    report = fraud_eval.score([case], [({"P-009"}, "review")], corpus="x.csv", source="fields")
    assert report.coverage_gap["mismatched_po"]["documents"] == 1
    assert report.coverage_gap["mismatched_po"]["flagged_incidentally"] == 1
    assert report.detection["documents_with_covered_fraud"] == 0


# --- rendering ------------------------------------------------------------


def test_rendered_page_passes_triage(tmp_path):
    """The bridge from row to picture has to produce something intake accepts,
    or the end-to-end path measures nothing but the renderer."""
    from verity.eval.render import render_case
    from verity.ingestion import router

    case = build_cases(rows=[_row()])[0]
    path = render_case(case, tmp_path)
    assert path.exists()
    assert router.route(path).status == router.ACCEPTED
