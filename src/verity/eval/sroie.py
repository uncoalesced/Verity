"""SROIE loader: the vendor and date labels CORD does not have.

Month 1 reported vendor and date as *unscored* rather than quietly counting them
as correct, because CORD-v2 labels only menu, sub_total and total. That was the
honest thing to do and it left two of the four fields unmeasured.

SROIE labels company, date, address and total on scanned receipts, so pairing it
with CORD closes the gap: CORD scores the rows and the arithmetic, SROIE scores
the supplier and the date.

The dataset is pulled through the same HF cache as CORD. If it is not reachable
the eval says so and stops -- it does not fall back to scoring three fields and
reporting the result as if four had been checked.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# The community mirror of ICDAR 2019 SROIE task 3 (key information extraction).
# Override with VERITY_SROIE_DATASET if a different mirror is preferred.
DATASET_ID = os.getenv("VERITY_SROIE_DATASET", "darentang/sroie")

# What SROIE calls the fields Verity cares about.
COMPANY_KEYS = ("company", "COMPANY")
DATE_KEYS = ("date", "DATE")
TOTAL_KEYS = ("total", "TOTAL")


def cache_dir() -> Path:
    return Path(os.getenv("HF_HOME", "./.cache/huggingface")).expanduser()


def _first(mapping: dict, keys: tuple[str, ...]):
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def parse_entities(raw: object) -> dict:
    """Flatten one SROIE annotation into the fields Verity extracts.

    Accepts either the parsed dict or the raw JSON string, because mirrors of
    this dataset differ on which they store.
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return {"vendor": None, "date": None, "total": None, "line_items": None}
    if not isinstance(raw, dict):
        return {"vendor": None, "date": None, "total": None, "line_items": None}

    return {
        "vendor": _first(raw, COMPANY_KEYS),
        "date": _first(raw, DATE_KEYS),
        "total": _first(raw, TOTAL_KEYS),
        # SROIE has no per-row labels; line items stay unscored on this corpus.
        "line_items": None,
    }


def _entities_of(row: dict) -> object:
    """Find the annotation block, whatever this mirror decided to call it."""
    for key in ("entities", "ground_truth", "parsed", "label"):
        if key in row:
            return row[key]
    return row


def load_sroie(split: str = "test", limit: int | None = None) -> Iterator[tuple[object, dict]]:
    """Yield (PIL image, ground-truth dict) pairs from the local cache."""
    from datasets import load_dataset

    ds = load_dataset(DATASET_ID, split=split, cache_dir=str(cache_dir()))
    for i, row in enumerate(ds):
        if limit is not None and i >= limit:
            return
        yield row["image"], parse_entities(_entities_of(row))
