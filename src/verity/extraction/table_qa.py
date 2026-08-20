"""Line-item table QA with TAPAS.

TAPAS reads a *table*, not a page image: it answers questions over rows that
document_qa (or a later table-detection stage) already pulled off the document.
"""

from __future__ import annotations

import functools

import pandas as pd
from transformers import pipeline

MODEL_ID = "google/tapas-base-finetuned-wtq"


@functools.lru_cache(maxsize=1)
def _pipe():
    return pipeline("table-question-answering", model=MODEL_ID)


def query_table(rows: list[dict], question: str) -> str:
    """Answer `question` over line-item `rows`. Returns "" for an empty table."""
    if not rows:
        return ""
    # TAPAS only handles string cells.
    table = pd.DataFrame(rows).astype(str)
    result = _pipe()(table=table, query=question)
    # `answer` prefixes the WTQ aggregator ("AVERAGE > 15.00"); `cells` is the raw values.
    return ", ".join(result.get("cells") or [])
