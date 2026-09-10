"""Shared fixtures.

Two things every test of the upper layers needs: a database that is not
Postgres, and an agent that does not download a checkpoint.
"""

import datetime as dt
from decimal import Decimal

import pytest
from PIL import Image
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from verity.agent.tools import Toolbox
from verity.db.models import Base
from verity.extraction.schema import ExtractedFields, LineItem


@pytest.fixture
def session_factory():
    """A throwaway SQLite database with the real schema on it.

    SQLite rather than Postgres so the suite runs anywhere. The models use
    portable column types, so the mapping being exercised is the real one.

    StaticPool pins every session to one connection. Without it an in-memory
    SQLite database is per-connection, and the API tests -- which run the app on
    a different thread -- would each get a fresh, empty database.
    """
    engine = create_engine(
        "sqlite://",
        future=True,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def session(session_factory):
    db = session_factory()
    try:
        yield db
    finally:
        db.close()


def clean_reading(**overrides) -> ExtractedFields:
    """A believable reading of a clean invoice."""
    base = {
        "vendor": "Northwind Supplies",
        "date": dt.date(2026, 6, 20),
        "total": Decimal("1240.55"),
        "line_items": [
            LineItem(name="Copier paper A4", amount=Decimal("496.22")),
            LineItem(name="Toner cartridge", amount=Decimal("744.33")),
        ],
        "signature_present": True,
        "confidence": 0.93,
    }
    base.update(overrides)
    return ExtractedFields(**base)


def fake_toolbox(fields: ExtractedFields | None = None, **overrides) -> Toolbox:
    """A toolbox that returns a fixed reading instead of running models."""
    reading = fields if fields is not None else clean_reading()
    defaults = {
        "load_image": lambda path: Image.new("RGB", (64, 64), "white"),
        "read_fields": lambda image, dayfirst=False: reading,
        "read_field": lambda image, field_name, question=None: "",
        "detect_signature": lambda image: (bool(reading.signature_present), 0.91),
        "history": lambda fields: [],
    }
    defaults.update(overrides)
    return Toolbox(**defaults)


@pytest.fixture
def receipt_png(tmp_path):
    """A small image with real ink on it, so intake accepts it."""
    path = tmp_path / "invoice.png"
    img = Image.new("RGB", (120, 120), "white")
    for x in range(10, 110):
        for y in range(40, 70):
            img.putpixel((x, y), (0, 0, 0))
    img.save(path)
    return path
