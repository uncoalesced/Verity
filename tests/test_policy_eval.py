"""The control eval scores the controls, not the fixtures."""

from verity.eval.cases import CASES, rows_for
from verity.eval.policy_eval import evaluate_cases, untested_rules
from verity.policy.library import POLICIES


def test_every_control_has_at_least_one_labelled_case():
    """A control nobody wrote a case for is a control nobody has checked."""
    report = evaluate_cases()
    assert untested_rules(report) == []


def test_all_labelled_cases_produce_exactly_the_expected_controls():
    report = evaluate_cases()
    wrong = [(o.name, o.missed, o.spurious) for o in report.outcomes if not o.exact]
    assert wrong == []


def test_the_clean_case_trips_nothing():
    report = evaluate_cases()
    clean = next(o for o in report.outcomes if o.name == "clean invoice")
    assert clean.fired == []
    assert clean.verdict == "pass"


def test_generated_rows_reconcile_exactly():
    """Fixtures must not leave an accidental gap for the arithmetic control."""
    for case in CASES:
        total = case.fields.total
        line_total = case.fields.line_item_total()
        if total is None or line_total is None or case.fields.subtotal is not None:
            continue
        if "inflated" in case.name:
            continue  # this one is meant to disagree
        assert line_total == total, case.name


def test_case_count_matches_the_library_size_expectation():
    assert len(POLICIES) == 14
    assert len(CASES) >= len(POLICIES)


def test_rows_for_sums_to_the_total():
    from decimal import Decimal

    total = Decimal("9803.25")
    assert sum(item.amount for item in rows_for(total)) == total
