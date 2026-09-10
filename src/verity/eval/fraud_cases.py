"""The held-out fraud set: labelled documents with deliberately injected violations.

`cases.py` holds nineteen cases written by hand, one per control, to answer
"does each control fire in isolation". They are still useful and still run --
but they are not evidence of much, because the same hand that wrote the control
wrote the case. This module builds the other kind of evidence: a corpus of
invoices nobody wrote per-control, carrying injected fraud with known labels.

The source is `sample/verity_sample_invoices_*.csv` -- synthetic invoice rows
with `fraud_type` and `is_fraudulent` label columns. What follows is every
judgement call made turning those rows into a scoreable eval set, written down
because a labelled set whose labelling is unexamined is worth less than no set
at all.

**The thresholds.** The generator injected `split_invoice` cases clustered at
48,670-49,997, which places its intended approval threshold at 50,000. That is
what `eval_config` uses. A consequence worth stating plainly: this is a corpus
of large invoices against a small approval limit, so P-009 (over the delegated
limit) fires on the large majority of documents, fraudulent or not. That is the
control doing its job -- routing large spend for sign-off -- not a false
positive, which is why P-009 is not one of the scored controls below.

**The approved-supplier list.** P-012 needs one, or it is disabled. It is built
from every supplier carrying at least one non-`ghost_vendor` row, which is what
a real supplier master holds: the suppliers you actually trade with. The three
ghost suppliers appear on no other row, so nothing is being smuggled in.

**The missing counterparties.** The CSVs label `duplicate_invoice` and
`split_invoice` rows but do *not* contain the prior document each one claims to
duplicate or sit beside -- the generator wrote the label without writing the
counterpart. Those priors are synthesised here (`_synthetic_priors`), and both
sides are visible in this file:

* a duplicate gets a prior with the same supplier, amount and invoice date -- a
  re-submission of the same invoice, which is exactly the shape P-002 is written
  for. **A duplicate re-issued under a different invoice date is not in this
  set, and P-002 would not catch it**: the rule compares dates exactly. That is
  a known, untested limitation, not a measured strength.
* a split gets a same-day sibling from the same supplier, priced inside the
  band just under the approval limit.

**The history each case sees** mirrors `verity.agent.history.db_history`: every
other document in the corpus from the same supplier within the lookback window.
Not a hand-picked neighbourhood -- so a clean document standing next to an
awkward neighbour can, and does, produce a genuine false positive.

**Two injected fraud types have no control at all.** `mismatched_po` needs a
purchase-order master Verity does not have, and `weekend_submission` needs
submission metadata that never reaches the document. They are reported as an
explicit coverage gap rather than quietly dropped or counted as misses against
controls that were never written to catch them.
"""

from __future__ import annotations

import csv
import datetime as dt
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path

from verity.extraction.schema import ExtractedFields
from verity.policy.library import PolicyConfig
from verity.policy.rules import PriorDocument, normalize_vendor

CORPUS_DIR = Path(__file__).resolve().parents[3] / "sample"
DEFAULT_CORPUS = CORPUS_DIR / "verity_sample_invoices_s_100.csv"

# Read off the generator's own split-invoice cluster (48,670-49,997), not picked
# to flatter the numbers. Change it and the splitting control stops lining up
# with the data.
APPROVAL_LIMIT = Decimal("50000.00")

# Same window `db_history` uses, for the same reason: a duplicate months apart is
# still a duplicate.
LOOKBACK_DAYS = 180

# Document ids for the priors that had to be synthesised, kept well clear of the
# corpus's own row numbering so a synthetic neighbour is obvious in any report.
SYNTHETIC_ID_BASE = 900_000

# Which control each injected fraud type is the job of.
FRAUD_TYPE_RULES: dict[str, frozenset[str]] = {
    "none": frozenset(),
    "altered_total": frozenset({"P-007"}),
    "round_number_amount": frozenset({"P-010"}),
    "duplicate_invoice": frozenset({"P-002"}),
    "split_invoice": frozenset({"P-011"}),
    "ghost_vendor": frozenset({"P-012"}),
}

# Injected fraud Verity has no control for. Scored as a coverage gap, reported
# separately, never counted against a control that does not exist.
UNCOVERED_FRAUD_TYPES: dict[str, str] = {
    "mismatched_po": "needs a purchase-order master; Verity has no PO data",
    "weekend_submission": "needs submission metadata; never present on the document itself",
}

# The controls this set can score. Everything else either cannot fire on these
# rows (no signature was checked, no intake was rejected) or fires on legitimate
# documents by design (P-009 routes large spend for sign-off). Their firing
# volume is still reported -- see `fraud_eval` -- just not as detection precision.
SCORED_RULES: frozenset[str] = frozenset().union(*FRAUD_TYPE_RULES.values())


@dataclass(frozen=True)
class Row:
    """One row of the source CSV, parsed."""

    invoice_id: str
    vendor: str
    invoice_date: dt.date | None
    submitted_date: dt.date | None
    subtotal: Decimal | None
    tax: Decimal | None
    total: Decimal | None
    currency: str
    confidence: float
    fraud_type: str
    is_fraudulent: bool
    notes: str


@dataclass
class FraudCase:
    """One document from the corpus, with the controls that ought to fire on it."""

    name: str
    document_id: int
    fields: ExtractedFields
    expected: frozenset[str]
    history: list[PriorDocument] = field(default_factory=list)
    config: PolicyConfig = field(default_factory=PolicyConfig)
    today: dt.date = field(default_factory=dt.date.today)
    fraud_type: str = "none"
    is_fraudulent: bool = False
    # Set when the row carries injected fraud no control covers.
    uncovered_reason: str | None = None
    currency: str = ""
    note: str = ""


def _money(value: str | None) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        return Decimal(value)
    except InvalidOperation:
        return None


def _date(value: str | None) -> dt.date | None:
    if not value:
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def load_rows(path: str | Path = DEFAULT_CORPUS) -> list[Row]:
    """Parse the source CSV. No labelling decisions happen here."""
    with Path(path).open(newline="", encoding="utf-8") as fh:
        return [
            Row(
                invoice_id=r["invoice_id"],
                vendor=r["vendor_name"],
                invoice_date=_date(r.get("invoice_date")),
                submitted_date=_date(r.get("submitted_date")),
                subtotal=_money(r.get("subtotal")),
                tax=_money(r.get("tax_amount")),
                total=_money(r.get("total_amount")),
                currency=r.get("currency", ""),
                confidence=float(r.get("ocr_confidence") or 0.0),
                fraud_type=r.get("fraud_type", "none"),
                is_fraudulent=str(r.get("is_fraudulent", "")).strip().lower() == "true",
                notes=r.get("notes", ""),
            )
            for r in csv.DictReader(fh)
        ]


def approved_vendors(rows: list[Row]) -> frozenset[str]:
    """Every supplier with at least one row that is not a ghost-vendor row."""
    ghosts = {r.vendor for r in rows if r.fraud_type == "ghost_vendor"}
    return frozenset({r.vendor for r in rows if r.vendor not in ghosts})


def eval_config(rows: list[Row]) -> PolicyConfig:
    """The thresholds this corpus is audited under. See the module docstring."""
    return PolicyConfig(approval_limit=APPROVAL_LIMIT, approved_vendors=approved_vendors(rows))


def _fields_from(row: Row) -> ExtractedFields:
    """The reading of a document, taken from the row rather than from a model.

    `signature_present` stays None -- the CSV says nothing about signatures, and
    None is Verity's "not checked", which keeps P-008 silent. Recording False
    would invent evidence of a missing signature nobody looked for.

    `line_items` are empty for the same reason: the CSV carries no rows. P-007
    still has real work to do, because subtotal and tax are both printed.
    """
    return ExtractedFields(
        vendor=row.vendor or None,
        date=row.invoice_date,
        total=row.total,
        subtotal=row.subtotal,
        tax=row.tax,
        line_items=[],
        signature_present=None,
        confidence=row.confidence,
        raw={"invoice_id": row.invoice_id, "currency": row.currency},
    )


def _split_sibling_total(index: int, limit: Decimal, proximity: Decimal) -> Decimal:
    """A same-supplier sibling priced inside the just-under-the-limit band.

    Derived from the row index so the set is byte-identical run to run -- an
    eval whose fixtures move is an eval whose numbers cannot be compared.
    """
    floor = limit * proximity
    span = limit - floor
    offset = Decimal(index * 137 % 1000) / Decimal(1000)
    return (floor + span * offset).quantize(Decimal("0.01"))


def _synthetic_priors(rows: list[Row], config: PolicyConfig) -> list[PriorDocument]:
    """The counterparties the generator labelled but never wrote.

    Every document returned here is invented by Verity, not by the corpus. It is
    kept in one function so what was added stays auditable in one place.
    """
    priors: list[PriorDocument] = []
    for index, row in enumerate(rows):
        if row.invoice_date is None or row.total is None or not row.vendor:
            continue
        if row.fraud_type == "duplicate_invoice":
            priors.append(
                PriorDocument(
                    document_id=SYNTHETIC_ID_BASE + index,
                    vendor=row.vendor,
                    total=row.total,
                    date=row.invoice_date,
                )
            )
        elif row.fraud_type == "split_invoice":
            priors.append(
                PriorDocument(
                    document_id=SYNTHETIC_ID_BASE + index,
                    vendor=row.vendor,
                    total=_split_sibling_total(index, config.approval_limit, config.split_proximity),
                    date=row.invoice_date,
                )
            )
    return priors


def build_ledger(rows: list[Row], config: PolicyConfig) -> list[PriorDocument]:
    """Every document in the corpus, plus the synthesised counterparties.

    This is the ledger a real deployment would be auditing against: the whole
    corpus, not a per-case neighbourhood chosen to make a control fire.
    """
    corpus = [
        PriorDocument(document_id=index + 1, vendor=row.vendor, total=row.total, date=row.invoice_date)
        for index, row in enumerate(rows)
        if row.invoice_date is not None and row.vendor
    ]
    return corpus + _synthetic_priors(rows, config)


def history_for(
    document_id: int,
    vendor: str,
    audited_on: dt.date,
    ledger: list[PriorDocument],
    lookback_days: int = LOOKBACK_DAYS,
) -> list[PriorDocument]:
    """What `db_history` would return for this document, against this ledger."""
    if not vendor:
        return []
    target = normalize_vendor(vendor)
    cutoff = audited_on - dt.timedelta(days=lookback_days)
    return [
        prior
        for prior in ledger
        if prior.document_id != document_id
        and prior.date is not None
        and prior.date >= cutoff
        and normalize_vendor(prior.vendor) == target
    ]


def build_cases(rows: list[Row] | None = None, path: str | Path = DEFAULT_CORPUS) -> list[FraudCase]:
    """Turn the corpus into labelled cases, one per row."""
    rows = rows if rows is not None else load_rows(path)
    config = eval_config(rows)
    ledger = build_ledger(rows, config)

    cases: list[FraudCase] = []
    for index, row in enumerate(rows):
        document_id = index + 1
        # An audit runs when the document arrives, not on some later calendar
        # date. Anchoring here is what stops a corpus spanning three years from
        # reading as a staleness epidemic that says nothing about the controls.
        audited_on = row.submitted_date or row.invoice_date or dt.date.today()
        cases.append(
            FraudCase(
                name=row.invoice_id,
                document_id=document_id,
                fields=_fields_from(row),
                expected=FRAUD_TYPE_RULES.get(row.fraud_type, frozenset()),
                history=history_for(document_id, row.vendor, audited_on, ledger),
                config=config,
                today=audited_on,
                fraud_type=row.fraud_type,
                is_fraudulent=row.is_fraudulent,
                uncovered_reason=UNCOVERED_FRAUD_TYPES.get(row.fraud_type),
                currency=row.currency,
                note=row.notes,
            )
        )
    return cases
