"""Normalising the whole-document parse.

No model runs here. `fields_from_cord` is pure, which is the point: the awkward
shapes real receipts produce can be checked without a GPU or a download.
"""

from decimal import Decimal

from verity.extraction.structured import fields_from_cord, line_items_from_menu

MULTI = {
    "menu": [
        {"nm": "Nasi Goreng", "cnt": "2", "unitprice": "30.000", "price": "60.000"},
        {"nm": "Es Teh", "cnt": "1", "price": "8.000"},
    ],
    "sub_total": {"subtotal_price": "68.000"},
    "total": {"total_price": "68.000"},
}


def test_every_row_is_read_not_just_the_first():
    """The Month 1 interface returned one item per document. This is the fix."""
    fields = fields_from_cord(MULTI)
    assert [item.name for item in fields.line_items] == ["Nasi Goreng", "Es Teh"]


def test_amounts_come_back_as_decimals():
    fields = fields_from_cord(MULTI)
    assert fields.total == Decimal("68000")
    assert fields.subtotal == Decimal("68000")
    assert fields.line_items[0].amount == Decimal("60000")
    assert fields.line_items[0].quantity == Decimal("2")


def test_single_row_receipt_stored_as_a_bare_dict():
    """CORD writes a one-row table as a dict rather than a list of one."""
    items = line_items_from_menu({"nm": "Kopi", "price": "12.000"})
    assert len(items) == 1
    assert items[0].name == "Kopi"


def test_rows_with_no_name_are_dropped():
    items = line_items_from_menu([{"price": "5.000"}, {"nm": "  ", "price": "1.000"}])
    assert items == []


def test_missing_blocks_do_not_raise():
    fields = fields_from_cord({"menu": [{"nm": "Only item"}]})
    assert fields.total is None
    assert fields.subtotal is None
    assert len(fields.line_items) == 1


def test_a_parse_that_is_not_a_dict_is_kept_rather_than_lost():
    fields = fields_from_cord("model returned prose", confidence=0.4)
    assert fields.total is None
    assert fields.confidence == 0.4
    assert fields.raw == {"parse": "model returned prose"}


def test_confidence_is_carried_onto_the_fields():
    assert fields_from_cord(MULTI, confidence=0.81).confidence == 0.81
