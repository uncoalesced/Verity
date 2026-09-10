"""The decision logic. Every rule is deterministic given the same document and
config, so these tests pin exact behaviour -- the wording of a threshold check
here decides whether real money gets held or released."""

from __future__ import annotations

import datetime as dt
from decimal import Decimal

from verity.extraction.schema import ExtractedFields, LineItem
from verity.policy import library, rules
from verity.policy.rules import AuditContext, PriorDocument

TODAY = dt.date(2026, 6, 1)


def ctx(fields=None, **overrides):
    kwargs = {
        "fields": fields or ExtractedFields(confidence=0.95),
        "config": library.PolicyConfig(),
        "document_id": 1,
        "filename": "doc.png",
        "ingestion_status": "accepted",
        "reject_reason": None,
        "history": [],
        "today": TODAY,
    }
    kwargs.update(overrides)
    return AuditContext(**kwargs)


# --- normalize_vendor --------------------------------------------------------


def test_normalize_vendor_folds_case_and_punctuation():
    assert rules.normalize_vendor("ACME Ltd.") == rules.normalize_vendor("acme ltd")


def test_normalize_vendor_handles_none_and_empty():
    assert rules.normalize_vendor(None) == ""
    assert rules.normalize_vendor("") == ""


# --- rule_intake_rejected -----------------------------------------------------


def test_rule_intake_rejected_fires_on_rejected_status():
    c = ctx(ingestion_status="rejected", reject_reason="corrupt image", filename="bad.png")
    finding = rules.rule_intake_rejected(c)
    assert finding.rule_id == "P-014"
    assert "corrupt image" in finding.message


def test_rule_intake_rejected_silent_when_accepted():
    assert rules.rule_intake_rejected(ctx()) is None


# --- rule_low_confidence -------------------------------------------------------


def test_rule_low_confidence_fires_below_threshold():
    c = ctx(ExtractedFields(confidence=0.3))
    finding = rules.rule_low_confidence(c)
    assert finding.rule_id == "P-013"


def test_rule_low_confidence_silent_at_threshold():
    c = ctx(ExtractedFields(confidence=0.60))
    assert rules.rule_low_confidence(c) is None


# --- rule_unsubstantiated_amount -----------------------------------------------


def test_rule_unsubstantiated_amount_fires_with_no_total():
    c = ctx(ExtractedFields(confidence=0.9))
    finding = rules.rule_unsubstantiated_amount(c)
    assert finding.rule_id == "P-001"


def test_rule_unsubstantiated_amount_fires_above_threshold_with_no_id():
    fields = ExtractedFields(confidence=0.9, total=Decimal("200"))
    finding = rules.rule_unsubstantiated_amount(ctx(fields))
    assert finding.rule_id == "P-001"


def test_rule_unsubstantiated_amount_silent_with_vendor():
    fields = ExtractedFields(confidence=0.9, total=Decimal("200"), vendor="Acme")
    assert rules.rule_unsubstantiated_amount(ctx(fields)) is None


def test_rule_unsubstantiated_amount_silent_below_threshold():
    fields = ExtractedFields(confidence=0.9, total=Decimal("50"))
    assert rules.rule_unsubstantiated_amount(ctx(fields)) is None


# --- rule_missing_vendor / rule_missing_date -----------------------------------


def test_rule_missing_vendor_fires():
    assert rules.rule_missing_vendor(ctx()).rule_id == "P-003"


def test_rule_missing_vendor_silent_when_present():
    fields = ExtractedFields(confidence=0.9, vendor="Acme")
    assert rules.rule_missing_vendor(ctx(fields)) is None


def test_rule_missing_date_fires():
    assert rules.rule_missing_date(ctx()).rule_id == "P-004"


def test_rule_missing_date_silent_when_present():
    fields = ExtractedFields(confidence=0.9, date=TODAY)
    assert rules.rule_missing_date(ctx(fields)) is None


# --- rule_stale_document / rule_future_dated -----------------------------------


def test_rule_stale_document_fires_past_window():
    fields = ExtractedFields(confidence=0.9, date=TODAY - dt.timedelta(days=100))
    finding = rules.rule_stale_document(ctx(fields))
    assert finding.rule_id == "P-005"


def test_rule_stale_document_silent_within_window():
    fields = ExtractedFields(confidence=0.9, date=TODAY - dt.timedelta(days=10))
    assert rules.rule_stale_document(ctx(fields)) is None


def test_rule_future_dated_fires():
    fields = ExtractedFields(confidence=0.9, date=TODAY + dt.timedelta(days=1))
    finding = rules.rule_future_dated(ctx(fields))
    assert finding.rule_id == "P-006"


def test_rule_stale_document_silent_for_future_dates():
    """Future dates belong to P-006, not P-005 -- the two must not both fire."""
    fields = ExtractedFields(confidence=0.9, date=TODAY + dt.timedelta(days=1))
    assert rules.rule_stale_document(ctx(fields)) is None


# --- rule_arithmetic_integrity --------------------------------------------------


def test_arithmetic_integrity_silent_when_rows_match_subtotal():
    fields = ExtractedFields(
        confidence=0.9,
        subtotal=Decimal("20.00"),
        line_items=[LineItem(name="a", amount=Decimal("10.00")), LineItem(name="b", amount=Decimal("10.00"))],
    )
    assert rules.rule_arithmetic_integrity(ctx(fields)) is None


def test_arithmetic_integrity_fires_when_subtotal_disagrees():
    fields = ExtractedFields(
        confidence=0.9,
        subtotal=Decimal("25.00"),
        line_items=[LineItem(name="a", amount=Decimal("10.00")), LineItem(name="b", amount=Decimal("10.00"))],
    )
    finding = rules.rule_arithmetic_integrity(ctx(fields))
    assert finding.rule_id == "P-007"


def test_arithmetic_integrity_fires_when_total_below_line_items():
    fields = ExtractedFields(
        confidence=0.9,
        total=Decimal("15.00"),
        line_items=[LineItem(name="a", amount=Decimal("10.00")), LineItem(name="b", amount=Decimal("10.00"))],
    )
    finding = rules.rule_arithmetic_integrity(ctx(fields))
    assert finding.rule_id == "P-007"
    assert "less than the sum" in finding.message


def test_arithmetic_integrity_allows_tax_and_service_uplift():
    fields = ExtractedFields(
        confidence=0.9,
        total=Decimal("25.00"),  # 25% uplift over 20 -- inside the 35% ratio
        line_items=[LineItem(name="a", amount=Decimal("10.00")), LineItem(name="b", amount=Decimal("10.00"))],
    )
    assert rules.rule_arithmetic_integrity(ctx(fields)) is None


def test_arithmetic_integrity_fires_when_uplift_is_unexplainable():
    fields = ExtractedFields(
        confidence=0.9,
        total=Decimal("40.00"),  # 100% over 20
        line_items=[LineItem(name="a", amount=Decimal("10.00")), LineItem(name="b", amount=Decimal("10.00"))],
    )
    finding = rules.rule_arithmetic_integrity(ctx(fields))
    assert finding.rule_id == "P-007"


def test_arithmetic_integrity_silent_with_no_line_items():
    fields = ExtractedFields(confidence=0.9, total=Decimal("40.00"))
    assert rules.rule_arithmetic_integrity(ctx(fields)) is None


def test_arithmetic_integrity_silent_when_subtotal_plus_tax_makes_the_total():
    fields = ExtractedFields(
        confidence=0.9,
        subtotal=Decimal("100.00"),
        tax=Decimal("18.00"),
        total=Decimal("118.00"),
    )
    assert rules.rule_arithmetic_integrity(ctx(fields)) is None


def test_arithmetic_integrity_catches_an_inflated_total_inside_the_tax_band():
    """The case the uplift ratio cannot see.

    117 over a 100 subtotal is a 17% uplift -- comfortably inside the 35% band
    that tax and service are allowed to explain, so the fallback check passes
    it. The document prints 12.00 of tax, so the sum it claims is 112.00, and
    the arithmetic check fails it.
    """
    fields = ExtractedFields(
        confidence=0.9,
        subtotal=Decimal("100.00"),
        tax=Decimal("12.00"),
        total=Decimal("117.00"),
    )
    finding = rules.rule_arithmetic_integrity(ctx(fields))
    assert finding.rule_id == "P-007"
    assert finding.evidence["expected_total"] == "112.00"
    assert finding.evidence["difference"] == "5.00"

    # Without the printed tax the same document passes -- which is exactly why
    # reading the tax off the page is worth doing.
    untaxed = ExtractedFields(confidence=0.9, subtotal=Decimal("100.00"), total=Decimal("117.00"))
    assert rules.rule_arithmetic_integrity(ctx(untaxed)) is None


def test_arithmetic_integrity_checks_the_total_even_when_the_rows_reconcile():
    """A reconciled subtotal used to end the check. It no longer does."""
    fields = ExtractedFields(
        confidence=0.9,
        subtotal=Decimal("20.00"),
        line_items=[LineItem(name="a", amount=Decimal("10.00")), LineItem(name="b", amount=Decimal("10.00"))],
        total=Decimal("60.00"),  # 200% of a subtotal the rows agree with
    )
    finding = rules.rule_arithmetic_integrity(ctx(fields))
    assert finding.rule_id == "P-007"
    assert "more than tax and service could explain" in finding.message


def test_arithmetic_integrity_fires_when_the_total_is_below_its_own_subtotal():
    fields = ExtractedFields(
        confidence=0.9,
        subtotal=Decimal("50.00"),
        total=Decimal("40.00"),
    )
    finding = rules.rule_arithmetic_integrity(ctx(fields))
    assert finding.rule_id == "P-007"
    assert "less than the subtotal" in finding.message


# --- rule_missing_signature -----------------------------------------------------


def test_missing_signature_fires_above_threshold():
    fields = ExtractedFields(confidence=0.9, total=Decimal("3000"), signature_present=False)
    finding = rules.rule_missing_signature(ctx(fields))
    assert finding.rule_id == "P-008"


def test_missing_signature_silent_when_present():
    fields = ExtractedFields(confidence=0.9, total=Decimal("3000"), signature_present=True)
    assert rules.rule_missing_signature(ctx(fields)) is None


def test_missing_signature_silent_when_not_checked():
    fields = ExtractedFields(confidence=0.9, total=Decimal("3000"), signature_present=None)
    assert rules.rule_missing_signature(ctx(fields)) is None


def test_missing_signature_silent_below_threshold():
    fields = ExtractedFields(confidence=0.9, total=Decimal("100"), signature_present=False)
    assert rules.rule_missing_signature(ctx(fields)) is None


# --- rule_over_approval_limit ----------------------------------------------------


def test_over_approval_limit_fires():
    fields = ExtractedFields(confidence=0.9, total=Decimal("15000"))
    finding = rules.rule_over_approval_limit(ctx(fields))
    assert finding.rule_id == "P-009"


def test_over_approval_limit_silent_at_limit():
    fields = ExtractedFields(confidence=0.9, total=Decimal("10000"))
    assert rules.rule_over_approval_limit(ctx(fields)) is None


# --- rule_round_amount -------------------------------------------------------------


def test_round_amount_fires_on_round_total():
    fields = ExtractedFields(confidence=0.9, total=Decimal("600"))
    finding = rules.rule_round_amount(ctx(fields))
    assert finding.rule_id == "P-010"


def test_round_amount_silent_below_floor():
    fields = ExtractedFields(confidence=0.9, total=Decimal("400"))
    assert rules.rule_round_amount(ctx(fields)) is None


def test_round_amount_silent_when_not_a_multiple_of_step():
    fields = ExtractedFields(confidence=0.9, total=Decimal("650"))
    assert rules.rule_round_amount(ctx(fields)) is None


# --- rule_duplicate_payment ---------------------------------------------------------


def test_duplicate_payment_fires_on_vendor_amount_date_match():
    fields = ExtractedFields(confidence=0.9, vendor="Acme Ltd.", total=Decimal("500"), date=TODAY)
    prior = PriorDocument(document_id=99, vendor="acme ltd", total=Decimal("500"), date=TODAY)
    finding = rules.rule_duplicate_payment(ctx(fields, document_id=1, history=[prior]))
    assert finding.rule_id == "P-002"
    assert finding.evidence["matched_document_id"] == 99


def test_duplicate_payment_ignores_its_own_document_id():
    fields = ExtractedFields(confidence=0.9, vendor="Acme", total=Decimal("500"), date=TODAY)
    prior = PriorDocument(document_id=1, vendor="Acme", total=Decimal("500"), date=TODAY)
    assert rules.rule_duplicate_payment(ctx(fields, document_id=1, history=[prior])) is None


def test_duplicate_payment_silent_on_partial_match():
    fields = ExtractedFields(confidence=0.9, vendor="Acme", total=Decimal("500"), date=TODAY)
    prior = PriorDocument(document_id=2, vendor="Acme", total=Decimal("400"), date=TODAY)
    assert rules.rule_duplicate_payment(ctx(fields, history=[prior])) is None


# --- rule_threshold_splitting --------------------------------------------------------


def test_threshold_splitting_fires_on_near_limit_siblings():
    fields = ExtractedFields(confidence=0.9, vendor="Acme", total=Decimal("9500"), date=TODAY)
    prior = PriorDocument(document_id=2, vendor="Acme", total=Decimal("9200"), date=TODAY - dt.timedelta(days=3))
    finding = rules.rule_threshold_splitting(ctx(fields, history=[prior]))
    assert finding.rule_id == "P-011"


def test_threshold_splitting_silent_outside_window():
    fields = ExtractedFields(confidence=0.9, vendor="Acme", total=Decimal("9500"), date=TODAY)
    prior = PriorDocument(document_id=2, vendor="Acme", total=Decimal("9200"), date=TODAY - dt.timedelta(days=30))
    assert rules.rule_threshold_splitting(ctx(fields, history=[prior])) is None


def test_threshold_splitting_silent_below_proximity():
    fields = ExtractedFields(confidence=0.9, vendor="Acme", total=Decimal("5000"), date=TODAY)
    prior = PriorDocument(document_id=2, vendor="Acme", total=Decimal("5000"), date=TODAY)
    assert rules.rule_threshold_splitting(ctx(fields, history=[prior])) is None


# --- rule_unapproved_vendor -----------------------------------------------------------


def test_unapproved_vendor_fires_when_list_configured():
    fields = ExtractedFields(confidence=0.9, vendor="Shadow Corp")
    c = ctx(fields, config=library.PolicyConfig(approved_vendors=frozenset({"acme"})))
    finding = rules.rule_unapproved_vendor(c)
    assert finding.rule_id == "P-012"


def test_unapproved_vendor_silent_when_on_list():
    fields = ExtractedFields(confidence=0.9, vendor="Acme Ltd.")
    c = ctx(fields, config=library.PolicyConfig(approved_vendors=frozenset({"acme ltd"})))
    assert rules.rule_unapproved_vendor(c) is None


def test_unapproved_vendor_silent_when_no_list_configured():
    fields = ExtractedFields(confidence=0.9, vendor="Shadow Corp")
    assert rules.rule_unapproved_vendor(ctx(fields)) is None


# --- evaluate / verdict / worst_severity -------------------------------------------------


def test_evaluate_clean_document_passes():
    fields = ExtractedFields(
        vendor="Acme Ltd.",
        date=TODAY,
        total=Decimal("42.00"),
        subtotal=Decimal("42.00"),
        line_items=[LineItem(name="widget", amount=Decimal("42.00"))],
        signature_present=True,
        confidence=0.95,
    )
    findings = rules.evaluate(ctx(fields))
    assert findings == []
    assert rules.verdict(findings) == rules.PASS
    assert rules.worst_severity(findings) is None


def test_evaluate_short_circuits_on_intake_rejection():
    """A rejected file only ever produces the one P-014 finding -- every other
    rule would just be commenting on fields that were never read."""
    c = ctx(ingestion_status="rejected", reject_reason="corrupt image: OSError")
    findings = rules.evaluate(c)
    assert [f.rule_id for f in findings] == ["P-014"]
    assert rules.verdict(findings) == rules.BLOCKED


def test_evaluate_sorts_worst_finding_first():
    fields = ExtractedFields(confidence=0.9)  # missing everything -> several findings
    findings = rules.evaluate(ctx(fields))
    assert len(findings) > 1
    ranks = [library.severity_rank(f.severity) for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_verdict_blocked_when_any_high_finding():
    findings = [
        rules.Finding(rule_id="P-003", severity=library.MEDIUM, message="m"),
        rules.Finding(rule_id="P-009", severity=library.HIGH, message="m"),
    ]
    assert rules.verdict(findings) == rules.BLOCKED


def test_verdict_review_when_only_medium_or_low():
    findings = [rules.Finding(rule_id="P-005", severity=library.LOW, message="m")]
    assert rules.verdict(findings) == rules.REVIEW


def test_verdict_pass_with_no_findings():
    assert rules.verdict([]) == rules.PASS


def test_worst_severity_picks_the_max():
    findings = [
        rules.Finding(rule_id="P-005", severity=library.LOW, message="m"),
        rules.Finding(rule_id="P-009", severity=library.HIGH, message="m"),
    ]
    assert rules.worst_severity(findings) == library.HIGH


def test_worst_severity_none_with_no_findings():
    assert rules.worst_severity([]) is None
