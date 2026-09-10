"""The database-backed history tool.

`verity.agent.tools.Toolbox.history` defaults to a no-op -- no ledger
configured, so the cross-document controls (duplicate payment, threshold
splitting) have nothing to compare against. `db_history` is the real version:
given the fields just read off a document, it returns the prior documents from
the same vendor for those rules to check against.

The query is scoped to vendor and a lookback window rather than pulling the
whole ledger into memory. Vendor matching itself happens in Python, after the
rows come back, because `normalize_vendor` folds case and punctuation that SQL
does not -- "ACME Ltd." and "acme ltd" have to compare equal, and that is a
Python-side rule, not a column.

ponytail: this reads the whole vendor-and-window slice into memory rather than
pushing the normalized comparison into SQL. Fine at the row counts one company's
expense ledger produces; add a normalized, indexed vendor column if this ever
needs to scale past that.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from decimal import Decimal

from sqlalchemy.orm import Session

from verity.db.models import Extraction
from verity.extraction.schema import ExtractedFields
from verity.policy.rules import PriorDocument, normalize_vendor

# How far back the ledger is searched for a match. Wider than the 14-day
# splitting window and the 90-day staleness window -- a duplicate payment
# months apart is still a duplicate payment.
LOOKBACK_DAYS = 180


def _to_prior(extraction: Extraction) -> PriorDocument:
    total = extraction.total
    return PriorDocument(
        document_id=extraction.document_id,
        vendor=extraction.vendor,
        total=None if total is None else Decimal(str(total)),
        date=extraction.date,
    )


def db_history(
    session: Session,
    lookback_days: int = LOOKBACK_DAYS,
    exclude_document_id: int | None = None,
) -> Callable[[ExtractedFields], list[PriorDocument]]:
    """Build a history tool backed by the `extractions` table.

    Takes the caller's `Session` rather than a session factory, and neither
    opens nor closes one. That is deliberate: the online path flushes an intake
    record and then audits inside the same transaction, so a lookup on a second
    connection would either miss that row or, on a shared connection, end the
    caller's transaction underneath it. Reading through the caller's session
    keeps the audit and the record it is about in one consistent view.

    `exclude_document_id` is what stops a document matching itself once its own
    row is visible in that transaction. Pass it whenever the document being
    audited already has an intake record.
    """

    def lookup(fields: ExtractedFields) -> list[PriorDocument]:
        if not fields.vendor:
            # Nothing to match on. The missing-vendor rule already speaks to
            # this document; a query with no vendor would only return noise.
            return []

        vendor = normalize_vendor(fields.vendor)
        cutoff = dt.date.today() - dt.timedelta(days=lookback_days)

        rows = (
            session.query(Extraction)
            .filter(Extraction.vendor.isnot(None))
            .filter(Extraction.date.isnot(None))
            .filter(Extraction.date >= cutoff)
            .all()
        )

        return [
            prior
            for prior in (_to_prior(row) for row in rows)
            if normalize_vendor(prior.vendor) == vendor and prior.document_id != exclude_document_id
        ]

    return lookup
