"""Labelled cases for scoring the controls.

The extraction eval answers "did we read the document correctly". This answers
the question a finance team actually cares about: "when a document has a problem
we care about, do we catch it, and do we leave the clean ones alone".

Every case is a set of already-read fields plus the exact control ids that ought
to fire. Extraction is deliberately out of the loop here -- mixing the two makes
a control failure and a reading failure indistinguishable in the same number.

Each case isolates one control. That is why the line items are generated to
reconcile to whatever total the case uses, and why the amounts are odd rather
than round: otherwise a case written to test the approval limit also trips the
arithmetic and round-amount controls, and the resulting precision number says
more about the fixtures than about the system.

The vendors and amounts are invented. Nothing here is a real supplier or a real
transaction.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from decimal import Decimal

from verity.extraction.schema import ExtractedFields, LineItem
from verity.policy.library import PolicyConfig
from verity.policy.rules import PriorDocument

# Every case is dated relative to this so the suite does not start failing when
# the calendar moves past a hard-coded date.
TODAY = dt.date(2026, 6, 30)

CENT = Decimal("0.01")


def _d(days_ago: int) -> dt.date:
    return TODAY - dt.timedelta(days=days_ago)


def rows_for(total: Decimal) -> list[LineItem]:
    """Two line items that add up to exactly `total`.

    Exactly, not approximately: the arithmetic control is supposed to fire on a
    gap, so a fixture that leaves one by accident would make every other case
    look like a false positive.
    """
    first = (total * Decimal("0.4")).quantize(CENT)
    return [
        LineItem(name="Copier paper A4", quantity=Decimal("10"), amount=first),
        LineItem(name="Toner cartridge", quantity=Decimal("2"), amount=total - first),
    ]


@dataclass
class Case:
    """One document, the controls it should trip, and why it exists."""

    name: str
    fields: ExtractedFields
    expected: set[str] = field(default_factory=set)
    history: list[PriorDocument] = field(default_factory=list)
    config: PolicyConfig = field(default_factory=PolicyConfig)
    ingestion_status: str = "accepted"
    reject_reason: str | None = None
    note: str = ""


def clean_fields(**overrides) -> ExtractedFields:
    """A document with nothing wrong with it, before overrides.

    Line items are derived from the total unless the caller supplies their own,
    so changing the amount in a case does not silently break reconciliation.
    """
    total = overrides.pop("total", Decimal("1240.55"))
    base = {
        "vendor": "Northwind Supplies",
        "date": _d(10),
        "total": total,
        "subtotal": None,
        "line_items": rows_for(total) if total is not None else [],
        "signature_present": True,
        "confidence": 0.93,
    }
    base.update(overrides)
    return ExtractedFields(**base)


DUP_PRIOR = PriorDocument(
    document_id=101,
    vendor="Northwind Supplies",
    total=Decimal("1240.55"),
    date=_d(10),
)

SPLIT_PRIORS = [
    PriorDocument(document_id=201, vendor="Contoso Fitout", total=Decimal("9612.40"), date=_d(9)),
    PriorDocument(document_id=202, vendor="Contoso Fitout", total=Decimal("9755.15"), date=_d(4)),
]


CASES: tuple[Case, ...] = (
    Case(
        name="clean invoice",
        fields=clean_fields(),
        expected=set(),
        note="The control that matters most is the one that stays quiet.",
    ),
    Case(
        name="duplicate of an invoice already filed",
        fields=clean_fields(),
        history=[DUP_PRIOR],
        expected={"P-002"},
    ),
    Case(
        name="no supplier name on the document",
        fields=clean_fields(vendor=None),
        expected={"P-003"},
    ),
    Case(
        name="no date on the document",
        fields=clean_fields(date=None),
        expected={"P-004"},
    ),
    Case(
        name="submitted six months late",
        fields=clean_fields(date=_d(190)),
        expected={"P-005"},
    ),
    Case(
        name="dated next month",
        fields=clean_fields(date=TODAY + dt.timedelta(days=21)),
        expected={"P-006"},
    ),
    Case(
        name="total inflated above the line items",
        fields=clean_fields(total=Decimal("1240.55"), line_items=rows_for(Decimal("410.20"))),
        expected={"P-007"},
        note="Rows sum to 410.20. A gap that size is not tax.",
    ),
    Case(
        name="subtotal does not match the rows",
        fields=clean_fields(subtotal=Decimal("980.00")),
        expected={"P-007"},
    ),
    Case(
        name="unsigned above the signature threshold",
        fields=clean_fields(total=Decimal("4820.75"), signature_present=False),
        expected={"P-008"},
    ),
    Case(
        name="signature not checked on a high-value document",
        fields=clean_fields(total=Decimal("4820.75"), signature_present=None),
        expected=set(),
        note="Absence of a check is not evidence of absence. P-008 stays silent.",
    ),
    Case(
        name="over the delegated approval limit",
        fields=clean_fields(total=Decimal("18432.75")),
        expected={"P-009"},
    ),
    Case(
        name="suspiciously round amount",
        fields=clean_fields(total=Decimal("1500.00")),
        expected={"P-010"},
    ),
    Case(
        name="third near-limit invoice from one supplier in two weeks",
        fields=clean_fields(vendor="Contoso Fitout", total=Decimal("9803.25"), date=_d(1)),
        history=SPLIT_PRIORS,
        expected={"P-011"},
    ),
    Case(
        name="near-limit invoice with no siblings",
        fields=clean_fields(vendor="Contoso Fitout", total=Decimal("9803.25"), date=_d(1)),
        expected=set(),
        note="One near-limit invoice is just an invoice. P-011 needs a pattern.",
    ),
    Case(
        name="supplier not on the approved list",
        fields=clean_fields(vendor="Fabrikam Trading"),
        config=PolicyConfig(approved_vendors=frozenset({"Northwind Supplies", "Contoso Fitout"})),
        expected={"P-012"},
    ),
    Case(
        name="supplier on the approved list, punctuation differs",
        fields=clean_fields(vendor="northwind supplies."),
        config=PolicyConfig(approved_vendors=frozenset({"Northwind Supplies", "Contoso Fitout"})),
        expected=set(),
        note="Matching is on normalised names, not exact strings.",
    ),
    Case(
        name="page too poor to read with confidence",
        fields=clean_fields(confidence=0.31),
        expected={"P-013"},
    ),
    Case(
        name="file rejected at intake",
        fields=ExtractedFields(),
        ingestion_status="rejected",
        reject_reason="image is blank (stddev 0.40)",
        expected={"P-014"},
        note="Nothing was read, so no other control gets to comment.",
    ),
    Case(
        name="no amount anywhere on the page",
        fields=clean_fields(total=None),
        expected={"P-001"},
    ),
)
