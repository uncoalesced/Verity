"""CORD loader.

CORD-v2 covers both receipt-level fields and line-item tables, so it exercises
Document QA and Table QA off one download. Each row is an image plus a
`ground_truth` JSON string; `gt_parse` holds the labelled fields.

Note on coverage: CORD-v2's public `gt_parse` contains menu / sub_total / total
only. There is no vendor or date label, so those fields evaluate with zero
support -- see extraction_eval.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DATASET_ID = "naver-clova-ix/cord-v2"

# Fields the extractor is asked for. Only those with a CORD label are scored.
FIELDS = ("vendor", "total", "date", "line_items")


def cache_dir() -> Path:
    return Path(os.getenv("HF_HOME", "./.cache/huggingface")).expanduser()


def parse_ground_truth(raw: str) -> dict:
    """Flatten one CORD `ground_truth` string into the fields Verity extracts."""
    gt = json.loads(raw).get("gt_parse", {})

    menu = gt.get("menu", [])
    if isinstance(menu, dict):  # CORD stores a single-item receipt as a bare dict
        menu = [menu]
    line_items = [item["nm"] for item in menu if isinstance(item, dict) and item.get("nm")]

    total = gt.get("total", {})
    return {
        "vendor": None,  # not labelled in CORD-v2
        "date": None,  # not labelled in CORD-v2
        "total": total.get("total_price") if isinstance(total, dict) else None,
        "line_items": line_items,
    }


def load_cord(split: str = "test", limit: int | None = None) -> Iterator[tuple[object, dict]]:
    """Yield (PIL image, ground-truth dict) pairs from the local cache."""
    from datasets import load_dataset

    ds = load_dataset(DATASET_ID, split=split, cache_dir=str(cache_dir()))
    for i, row in enumerate(ds):
        if limit is not None and i >= limit:
            return
        yield row["image"], parse_ground_truth(row["ground_truth"])
