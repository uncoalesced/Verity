"""CORD ground truth is inconsistently shaped -- a one-item receipt stores `menu` as a
bare dict instead of a list. Getting that wrong silently drops line-item labels."""

import json

from verity.eval.datasets import parse_ground_truth


def gt(parse):
    return json.dumps({"gt_parse": parse})


def test_single_item_menu_stored_as_dict():
    parsed = parse_ground_truth(gt({"menu": {"nm": "-TICKET CP", "price": "60.000"}, "total": {"total_price": "60.000"}}))
    assert parsed["line_items"] == ["-TICKET CP"]
    assert parsed["total"] == "60.000"


def test_multi_item_menu_stored_as_list():
    parsed = parse_ground_truth(
        gt({"menu": [{"nm": "J.STB PROMO"}, {"nm": "Y.B.BAT"}], "total": {"total_price": "91000"}})
    )
    assert parsed["line_items"] == ["J.STB PROMO", "Y.B.BAT"]


def test_missing_sections_do_not_raise():
    parsed = parse_ground_truth(gt({}))
    assert parsed == {"vendor": None, "date": None, "total": None, "line_items": []}


def test_vendor_and_date_are_unlabelled_in_cord():
    parsed = parse_ground_truth(gt({"menu": [{"nm": "x"}], "total": {"total_price": "1"}}))
    assert parsed["vendor"] is None and parsed["date"] is None
