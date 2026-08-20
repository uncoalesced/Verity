"""Scoring math. If these drift, every accuracy number the project reports is wrong."""

import pytest

from verity.eval.extraction_eval import (
    Counts,
    build_report,
    normalize_money,
    normalize_text,
    prf,
    score_multiset,
    score_scalar,
    split_items,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("60.000", "60000"), ("Rp 91,000", "91000"), ("60000", "60000"), ("", "")],
)
def test_normalize_money_drops_separators(raw, expected):
    assert normalize_money(raw) == expected


def test_normalize_text_ignores_case_and_punctuation():
    assert normalize_text("J.STB  PROMO") == normalize_text("j stb promo")


def test_split_items():
    assert split_items("J.STB PROMO, Y.B.BAT and Y.BASO") == ["J.STB PROMO", "Y.B.BAT", "Y.BASO"]


def test_score_scalar_exact_match():
    assert score_scalar("60.000", "60000", "total") == (1, 0, 0)


def test_score_scalar_wrong_answer_is_fp_and_fn():
    assert score_scalar("70000", "60000", "total") == (0, 1, 1)


def test_score_scalar_empty_prediction_is_fn_only():
    assert score_scalar("", "60000", "total") == (0, 0, 1)


def test_score_scalar_prediction_against_empty_label_is_fp():
    assert score_scalar("70000", "", "total") == (0, 1, 0)


def test_score_multiset_counts_duplicates():
    # two "cola" predicted, one labelled -> 1 tp, 1 fp; "fries" missed -> 1 fn
    assert score_multiset(["cola", "COLA"], ["cola", "fries"], "line_items") == (1, 1, 1)


def test_score_multiset_empty_prediction():
    assert score_multiset([], ["cola", "fries"], "line_items") == (0, 0, 2)


def test_prf_math():
    scores = prf(Counts(tp=3, fp=1, fn=2))
    assert scores["precision"] == 0.75
    assert scores["recall"] == 0.6
    assert scores["f1"] == pytest.approx(0.6667, abs=1e-4)
    assert scores["support"] == 5


def test_prf_no_predictions_is_zero_not_crash():
    assert prf(Counts()) == {"precision": 0.0, "recall": 0.0, "f1": 0.0, "support": 0, "tp": 0, "fp": 0, "fn": 0, "docs": 0}


def test_build_report_micro_sums_all_fields():
    counts = {"total": Counts(tp=2, fp=1, fn=1, docs=3), "line_items": Counts(tp=4, fp=2, fn=3, docs=3)}
    report = build_report("test", 3, counts, unscored=["vendor", "date"])

    assert report.micro["tp"] == 6
    assert report.micro["precision"] == pytest.approx(6 / 9, abs=1e-4)
    assert report.micro["recall"] == pytest.approx(6 / 10, abs=1e-4)
    assert report.per_field["total"]["precision"] == pytest.approx(2 / 3, abs=1e-4)
    assert report.unscored_fields == ["vendor", "date"]


def test_partially_labelled_field_is_not_reported_as_unscored():
    """One receipt without a total must not mark the whole field unscorable."""
    counts = {"total": Counts(tp=2, fp=0, fn=0, docs=2)}
    report = build_report("test", 3, counts, unscored=["total", "vendor"])
    assert report.unscored_fields == ["vendor"]
