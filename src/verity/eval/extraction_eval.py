"""Field-level precision/recall for the extraction stack against CORD.

Micro-averaged over documents. Scalar fields (vendor, total, date) score one
prediction against one label; line_items scores as a multiset so a receipt with
two identical rows needs two correct predictions.

Fields CORD does not label are reported with support 0 and no score rather than
being silently counted as correct.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field

from verity.eval.datasets import FIELDS, load_cord

MONEY_FIELDS = {"total"}
LIST_FIELDS = {"line_items"}


def normalize_text(value: str) -> str:
    """Casefold and drop punctuation so 'J.STB PROMO' == 'j stb promo'."""
    return re.sub(r"\s+", " ", re.sub(r"[^0-9a-z]+", " ", str(value).lower())).strip()


def normalize_money(value: str) -> str:
    """Digits only. CORD prices use '.' as a thousands separator ('60.000' == 60000)."""
    # ponytail: no currency/decimal awareness -- fine for CORD (rupiah, no cents),
    # revisit when the corpus has decimal currencies.
    return re.sub(r"\D", "", str(value))


def normalize(value: str, field_name: str) -> str:
    return normalize_money(value) if field_name in MONEY_FIELDS else normalize_text(value)


def split_items(answer: str) -> list[str]:
    """Turn one free-text answer into candidate line items."""
    return [part.strip() for part in re.split(r"[,;\n]| and ", str(answer)) if part.strip()]


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    docs: int = 0

    def add(self, tp: int, fp: int, fn: int) -> None:
        self.tp += tp
        self.fp += fp
        self.fn += fn
        self.docs += 1


def score_scalar(pred: str, gold: str, field_name: str) -> tuple[int, int, int]:
    """(tp, fp, fn) for one predicted value against one label."""
    p, g = normalize(pred, field_name), normalize(gold, field_name)
    if not g:
        return 0, (1 if p else 0), 0
    if p == g:
        return 1, 0, 0
    return 0, (1 if p else 0), 1


def score_multiset(preds: list[str], golds: list[str], field_name: str) -> tuple[int, int, int]:
    """(tp, fp, fn) treating both sides as multisets of normalized strings."""
    p = Counter(n for n in (normalize(x, field_name) for x in preds) if n)
    g = Counter(n for n in (normalize(x, field_name) for x in golds) if n)
    tp = sum((p & g).values())
    return tp, sum(p.values()) - tp, sum(g.values()) - tp


def prf(counts: Counts) -> dict:
    precision = counts.tp / (counts.tp + counts.fp) if counts.tp + counts.fp else 0.0
    recall = counts.tp / (counts.tp + counts.fn) if counts.tp + counts.fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "support": counts.tp + counts.fn,
        **asdict(counts),
    }


@dataclass
class Report:
    split: str
    documents: int = 0
    per_field: dict = field(default_factory=dict)
    micro: dict = field(default_factory=dict)
    unscored_fields: list = field(default_factory=list)


def build_report(split: str, documents: int, counts: dict[str, Counts], unscored: list[str]) -> Report:
    micro = Counts()
    for name, c in counts.items():
        micro.tp += c.tp
        micro.fp += c.fp
        micro.fn += c.fn
    micro.docs = documents
    return Report(
        split=split,
        documents=documents,
        per_field={name: prf(c) for name, c in counts.items()},
        micro=prf(micro),
        # A field is only unscored if *no* document labelled it; a single receipt
        # missing a total does not make "total" unscorable.
        unscored_fields=[name for name in unscored if name not in counts],
    )


def evaluate(split: str = "test", limit: int | None = 10) -> Report:
    from verity.extraction.document_qa import extract_field

    counts: dict[str, Counts] = {}
    unscored: set[str] = set()
    documents = 0

    for image, gold in load_cord(split=split, limit=limit):
        documents += 1
        for name in FIELDS:
            truth = gold.get(name)
            if truth is None:
                unscored.add(name)
                continue
            answer = extract_field(image, name)
            if name in LIST_FIELDS:
                scores = score_multiset(split_items(answer), truth, name)
            else:
                scores = score_scalar(answer, truth, name)
            counts.setdefault(name, Counts()).add(*scores)
        print(f"  scored {documents} document(s)", flush=True)

    return build_report(split, documents, counts, sorted(unscored))


def print_report(report: Report) -> None:
    print(f"\nCORD {report.split} -- {report.documents} documents\n")
    print(f"{'field':<14}{'precision':>10}{'recall':>10}{'f1':>8}{'support':>9}")
    print("-" * 51)
    for name, s in report.per_field.items():
        print(f"{name:<14}{s['precision']:>10.3f}{s['recall']:>10.3f}{s['f1']:>8.3f}{s['support']:>9}")
    m = report.micro
    print("-" * 51)
    print(f"{'MICRO':<14}{m['precision']:>10.3f}{m['recall']:>10.3f}{m['f1']:>8.3f}{m['support']:>9}")
    if report.unscored_fields:
        print(f"\nunscored (no CORD label): {', '.join(report.unscored_fields)}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Field-level precision/recall against CORD")
    ap.add_argument("--split", default="test", choices=["train", "validation", "test"])
    ap.add_argument("--limit", type=int, default=10, help="documents to score (0 = all)")
    ap.add_argument("--out", default="eval_report.json")
    args = ap.parse_args()

    report = evaluate(split=args.split, limit=args.limit or None)
    print_report(report)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(asdict(report), fh, indent=2)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
