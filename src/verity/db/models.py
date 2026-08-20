from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Document(Base):
    """One uploaded file. Status is set by the ingestion router before extraction runs."""

    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_path: Mapped[str] = mapped_column(Text)
    filename: Mapped[str] = mapped_column(String(255))
    # "pdf" | "image" | None when the router could not identify it
    format: Mapped[str | None] = mapped_column(String(16))
    # "accepted" | "rejected" -- see verity.ingestion.router
    ingestion_status: Mapped[str] = mapped_column(String(16))
    reject_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    extractions: Mapped[list[Extraction]] = relationship(back_populates="document", cascade="all, delete-orphan")


class Extraction(Base):
    """Structured fields pulled off one document by the extraction models."""

    __tablename__ = "extractions"

    id: Mapped[int] = mapped_column(primary_key=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), index=True)

    vendor: Mapped[str | None] = mapped_column(String(255))
    line_items: Mapped[list | None] = mapped_column(JSON)
    total: Mapped[float | None] = mapped_column(Numeric(14, 2))
    date: Mapped[dt.date | None] = mapped_column(Date)
    signature_present: Mapped[bool | None] = mapped_column(Boolean)
    confidence: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    document: Mapped[Document] = relationship(back_populates="extractions")
