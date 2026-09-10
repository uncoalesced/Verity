"""db_history: the ledger-backed version of Toolbox.history. Runs against an
in-memory sqlite database rather than the configured Postgres -- the query
shape and the vendor/window scoping are what's under test, not the driver."""

from __future__ import annotations

import datetime as dt
from decimal import Decimal

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from verity.agent.history import db_history
from verity.db.models import Base, Document, Extraction
from verity.extraction.schema import ExtractedFields

TODAY = dt.date.today()


def make_session_maker():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def seed(session_maker, rows):
    """rows: (document_id, vendor, total, date) tuples."""
    with session_maker() as session:
        for doc_id, vendor, total, date in rows:
            session.add(
                Document(
                    id=doc_id,
                    source_path=f"/{doc_id}",
                    filename=f"{doc_id}.png",
                    format="image",
                    ingestion_status="accepted",
                )
            )
            session.add(Extraction(document_id=doc_id, vendor=vendor, total=total, date=date, confidence=0.9))
        session.commit()
    return session_maker


def test_matches_on_normalized_vendor():
    session_maker = seed(
        make_session_maker(),
        [(1, "Acme Ltd.", Decimal("100.00"), TODAY), (2, "Other Corp", Decimal("50.00"), TODAY)],
    )
    lookup = db_history(session_maker())

    priors = lookup(ExtractedFields(vendor="acme ltd", total=Decimal("100.00"), date=TODAY))

    assert [p.document_id for p in priors] == [1]
    assert priors[0].total == Decimal("100.00")
    assert priors[0].date == TODAY


def test_returns_nothing_without_a_vendor_on_the_document_just_read():
    session_maker = seed(make_session_maker(), [(1, "Acme", Decimal("100.00"), TODAY)])
    lookup = db_history(session_maker())

    assert lookup(ExtractedFields(vendor=None)) == []


def test_excludes_the_document_being_re_audited():
    session_maker = seed(make_session_maker(), [(1, "Acme", Decimal("100.00"), TODAY)])
    lookup = db_history(session_maker(), exclude_document_id=1)

    assert lookup(ExtractedFields(vendor="Acme")) == []


def test_respects_the_lookback_window():
    old_date = TODAY - dt.timedelta(days=400)
    session_maker = seed(make_session_maker(), [(1, "Acme", Decimal("100.00"), old_date)])
    lookup = db_history(session_maker(), lookback_days=180)

    assert lookup(ExtractedFields(vendor="Acme")) == []


def test_a_document_within_the_window_is_still_found():
    recent = TODAY - dt.timedelta(days=5)
    session_maker = seed(make_session_maker(), [(1, "Acme", Decimal("100.00"), recent)])
    lookup = db_history(session_maker(), lookback_days=180)

    assert [p.document_id for p in lookup(ExtractedFields(vendor="Acme"))] == [1]


def test_ignores_rows_with_no_vendor_or_no_date():
    session_maker = seed(
        make_session_maker(),
        [(1, None, Decimal("100.00"), TODAY), (2, "Acme", Decimal("50.00"), None)],
    )
    lookup = db_history(session_maker())

    assert lookup(ExtractedFields(vendor="Acme")) == []
