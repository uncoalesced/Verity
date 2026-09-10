"""Reading numbers and dates off a document.

These are the two conversions that turn a picture into money. A silent mistake
here does not crash anything -- it produces a plausible wrong amount, which is
the worst failure mode this system has.
"""

import datetime as dt
from decimal import Decimal

import pytest

from verity.extraction.schema import ExtractedFields, LineItem, parse_date, parse_money


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("1,234.56", "1234.56"),      # US grouping
        ("1.234,56", "1234.56"),      # European grouping
        ("60.000", "60000"),          # Indonesian rupiah, no cents
        ("60,000", "60000"),
        ("1.234.567", "1234567"),     # repeated separator is always grouping
        ("$1,299.99", "1299.99"),
        ("Rp 45.000", "45000"),
        ("12.50", "12.50"),           # two-digit tail is decimals
        ("-89.10", "-89.10"),
        (Decimal("7.25"), "7.25"),
        (42, "42"),
    ],
)
def test_parse_money_handles_both_separator_conventions(raw, expected):
    assert parse_money(raw) == Decimal(expected)


@pytest.mark.parametrize("raw", [None, "", "n/a", "-", "...", "TOTAL"])
def test_parse_money_returns_none_rather_than_guessing(raw):
    assert parse_money(raw) is None


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2026-03-14", dt.date(2026, 3, 14)),
        ("14/03/2026", dt.date(2026, 3, 14)),   # unambiguous: no 14th month
        ("03/14/2026", dt.date(2026, 3, 14)),
        ("14 Mar 2026", dt.date(2026, 3, 14)),
        ("March 14 2026", dt.date(2026, 3, 14)),
        ("14th March 2026", dt.date(2026, 3, 14)),
        ("14.03.2026", dt.date(2026, 3, 14)),
    ],
)
def test_parse_date_reads_the_formats_receipts_use(raw, expected):
    assert parse_date(raw) == expected


def test_ambiguous_date_follows_the_dayfirst_flag():
    assert parse_date("03/04/2026") == dt.date(2026, 3, 4)
    assert parse_date("03/04/2026", dayfirst=True) == dt.date(2026, 4, 3)


@pytest.mark.parametrize("raw", [None, "", "sometime", "99/99/9999"])
def test_parse_date_returns_none_on_anything_it_cannot_read(raw):
    assert parse_date(raw) is None


def test_line_item_amount_is_computed_when_not_printed():
    item = LineItem(name="Toner", quantity=Decimal("3"), unit_price=Decimal("42.50"))
    assert item.resolved_amount() == Decimal("127.50")


def test_printed_amount_wins_over_the_computed_one():
    item = LineItem(
        name="Toner", quantity=Decimal("3"), unit_price=Decimal("42.50"), amount=Decimal("120.00")
    )
    assert item.resolved_amount() == Decimal("120.00")


def test_line_item_total_ignores_rows_with_no_amount():
    fields = ExtractedFields(
        line_items=[
            LineItem(name="Paper", amount=Decimal("10.00")),
            LineItem(name="Unreadable row"),
            LineItem(name="Toner", amount=Decimal("15.50")),
        ]
    )
    assert fields.line_item_total() == Decimal("25.50")


def test_line_item_total_is_none_when_no_row_carried_an_amount():
    fields = ExtractedFields(line_items=[LineItem(name="Unreadable")])
    assert fields.line_item_total() is None


def test_money_survives_serialisation_as_a_string_not_a_float():
    fields = ExtractedFields(total=Decimal("1240.55"), date=dt.date(2026, 3, 14))
    data = fields.as_dict()
    assert data["total"] == "1240.55"
    assert data["date"] == "2026-03-14"
