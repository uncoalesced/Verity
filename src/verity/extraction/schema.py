"""What a read document looks like once the models are done with it.

Everything downstream -- the rules, the agent, the API, the database -- speaks
`ExtractedFields`. The parsing helpers live here too, because turning "Rp
60.000" or "1,234.56" into a number the arithmetic check can trust is where
quiet, expensive mistakes get made.

Money is `Decimal` throughout. Floats are not allowed near an amount that
somebody is going to pay.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation

# Currency symbols and codes stripped before a number is parsed.
_CURRENCY = re.compile(r"(?i)\b(?:usd|eur|gbp|idr|rp|inr|jpy|aud|cad|chf|sgd)\b|[$€£¥₹]")
_NOT_NUMBER = re.compile(r"[^0-9.,\-]")

# Order matters. ISO first because it is never ambiguous, then month-first,
# then day-first. A genuinely ambiguous date like 03/04/2026 is therefore read
# month-first by default and day-first when `dayfirst=True` reorders this list.
# Dotted dates are the exception: 14.03.2026 is a European convention and has no
# month-first reading in circulation.
DATE_FORMATS = (
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%m/%d/%Y",
    "%d/%m/%Y",
    "%m-%d-%Y",
    "%d-%m-%Y",
    "%d.%m.%Y",
    "%d %b %Y",
    "%d %B %Y",
    "%b %d %Y",
    "%B %d %Y",
    "%m/%d/%y",
    "%d/%m/%y",
)

_DATE_CLEAN = re.compile(r",")
_ORDINAL = re.compile(r"(?i)(\d{1,2})(st|nd|rd|th)\b")


def parse_money(value: object) -> Decimal | None:
    """Parse an amount written the way a receipt writes it.

    Handles both separator conventions. When both a comma and a dot appear, the
    rightmost one is the decimal point ("1.234,56" and "1,234.56" both parse to
    1234.56). When only one appears and it is followed by exactly three digits,
    it is read as a thousands separator -- so Indonesian "60.000" is sixty
    thousand, not sixty. Returns None rather than guessing on anything else.
    """
    if value is None:
        return None
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)

    text = _NOT_NUMBER.sub("", _CURRENCY.sub(" ", str(value))).strip()
    if not text or set(text) <= {"-", ".", ","}:
        return None

    negative = text.startswith("-")
    text = text.lstrip("-").replace("-", "")

    has_dot, has_comma = "." in text, "," in text
    if has_dot and has_comma:
        decimal_sep = "." if text.rfind(".") > text.rfind(",") else ","
        thousands_sep = "," if decimal_sep == "." else "."
        text = text.replace(thousands_sep, "").replace(decimal_sep, ".")
    elif has_dot or has_comma:
        sep = "." if has_dot else ","
        parts = text.split(sep)
        tail = parts[-1]
        # Repeated separators, or a 3-digit tail, means grouping not decimals.
        if len(parts) > 2 or (len(tail) == 3 and parts[0]):
            text = text.replace(sep, "")
        else:
            text = text.replace(sep, ".")

    try:
        amount = Decimal(text)
    except InvalidOperation:
        return None
    return -amount if negative else amount


def parse_date(value: object, dayfirst: bool = False) -> dt.date | None:
    """Parse a date off a document, or return None.

    `dayfirst` picks the reading for genuinely ambiguous dates like 03/04/2024.
    An unambiguous date (a day past 12 in the first position) is read correctly
    whatever the flag says, because the ambiguous format simply fails to parse.
    """
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value

    text = _ORDINAL.sub(r"\1", _DATE_CLEAN.sub(" ", str(value))).strip()
    text = re.sub(r"\s+", " ", text)
    if not text:
        return None

    formats = list(DATE_FORMATS)
    if dayfirst:
        formats.sort(key=lambda f: 0 if f.startswith("%d") else 1)

    for fmt in formats:
        try:
            return dt.datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def _num(value: Decimal | None) -> str | None:
    """Serialise money as a string. JSON floats lose cents; strings do not."""
    return None if value is None else str(value)


@dataclass
class LineItem:
    """One row of a document. `amount` is the extended price for the row."""

    name: str
    quantity: Decimal | None = None
    unit_price: Decimal | None = None
    amount: Decimal | None = None

    def resolved_amount(self) -> Decimal | None:
        """The row's contribution to the total, computed if it was not printed."""
        if self.amount is not None:
            return self.amount
        if self.quantity is not None and self.unit_price is not None:
            return self.quantity * self.unit_price
        return self.unit_price

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "quantity": _num(self.quantity),
            "unit_price": _num(self.unit_price),
            "amount": _num(self.amount),
        }


@dataclass
class ExtractedFields:
    """The structured reading of one document.

    `confidence` is the model's own reading confidence, 0.0-1.0. Anything the
    model did not find is None -- never a zero, never an empty string standing in
    for a real value, because "we could not read the total" and "the total is
    nothing" lead to opposite decisions.
    """

    vendor: str | None = None
    date: dt.date | None = None
    total: Decimal | None = None
    line_items: list[LineItem] = field(default_factory=list)
    subtotal: Decimal | None = None
    # Tax as printed on the document. When it is present alongside a subtotal,
    # the arithmetic control (P-007) stops guessing at an "explainable uplift"
    # ratio and checks the sum the document itself claims: subtotal + tax must
    # equal the total. A forged total that still sits inside a plausible tax
    # band is only catchable this way.
    tax: Decimal | None = None
    signature_present: bool | None = None
    confidence: float = 0.0
    # Whatever the model emitted before normalisation, kept for the audit trail.
    raw: dict = field(default_factory=dict)

    def line_item_total(self) -> Decimal | None:
        """Sum of the rows, or None when no row carried a usable amount."""
        amounts = [a for a in (item.resolved_amount() for item in self.line_items) if a is not None]
        return sum(amounts, Decimal("0")) if amounts else None

    def as_dict(self) -> dict:
        data = asdict(self)
        data["date"] = self.date.isoformat() if self.date else None
        data["total"] = _num(self.total)
        data["subtotal"] = _num(self.subtotal)
        data["tax"] = _num(self.tax)
        data["line_items"] = [item.as_dict() for item in self.line_items]
        return data
