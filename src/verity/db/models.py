from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
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


class AuditRun(Base):
    """One pass of the agent over one document, and the decision it reached.

    A run is kept whole: the verdict, the fields it was based on, every finding
    and every step the agent took. Six months later the question is never "what
    does the model say now" -- it is "what did this system decide, on what, and
    why", and that has to be answerable without re-running anything.
    """

    __tablename__ = "audit_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    # The id carried through the trace and the API, so a log line and a row match.
    run_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    document_id: Mapped[int | None] = mapped_column(
        ForeignKey("documents.id", ondelete="SET NULL"), index=True
    )
    filename: Mapped[str] = mapped_column(String(255))

    # "pass" | "review" | "blocked" -- see verity.policy.rules.verdict
    verdict: Mapped[str] = mapped_column(String(16), index=True)
    worst_severity: Mapped[str | None] = mapped_column(String(16))
    ingestion_status: Mapped[str] = mapped_column(String(16))
    reject_reason: Mapped[str | None] = mapped_column(Text)

    # The reading the decision was made on, and the thresholds in force at the
    # time. Storing the config with the run is what makes an old verdict
    # reproducible after somebody raises the approval limit.
    fields: Mapped[dict | None] = mapped_column(JSON)
    config: Mapped[dict | None] = mapped_column(JSON)

    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    findings: Mapped[list[Finding]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="Finding.id"
    )
    steps: Mapped[list[TraceStep]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="TraceStep.step_index"
    )
    reviews: Mapped[list[ReviewDecision]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="ReviewDecision.id"
    )


class Finding(Base):
    """One control that fired on one run, with the policy language it fired under.

    The policy text is copied onto the row rather than referenced by id. The
    library is edited over time; a finding has to keep quoting the wording that
    was actually in force when the document was held.
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"), index=True
    )

    rule_id: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    message: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict | None] = mapped_column(JSON)
    policy_title: Mapped[str | None] = mapped_column(String(255))
    policy_text: Mapped[str | None] = mapped_column(Text)

    run: Mapped[AuditRun] = relationship(back_populates="findings")


class TraceStep(Base):
    """One tool call the agent made, in the order it made it."""

    __tablename__ = "trace_steps"

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"), index=True
    )

    step_index: Mapped[int] = mapped_column(Integer)
    tool: Mapped[str] = mapped_column(String(64))
    args: Mapped[dict | None] = mapped_column(JSON)
    result: Mapped[dict | None] = mapped_column(JSON)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[float | None] = mapped_column(Float)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    note: Mapped[str | None] = mapped_column(Text)

    run: Mapped[AuditRun] = relationship(back_populates="steps")


class ReviewDecision(Base):
    """What a person decided after reading the run.

    Verity holds and routes; it never approves. This table is where the human
    judgement lands, and it is append-only: a decision that gets overturned
    stays on the record next to the one that replaced it. Deleting the earlier
    view of the facts is exactly what an audit trail exists to prevent.

    `overrides_verdict` marks the case a controller most wants to see later --
    a reviewer releasing a payment the controls had blocked.
    """

    __tablename__ = "review_decisions"

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"), index=True
    )

    # "approved" | "rejected" | "needs_info"
    decision: Mapped[str] = mapped_column(String(16), index=True)
    reviewer: Mapped[str] = mapped_column(String(255))
    rationale: Mapped[str | None] = mapped_column(Text)
    # True when the reviewer cleared a document the controls had blocked.
    overrides_verdict: Mapped[bool] = mapped_column(Boolean, default=False)
    decided_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    run: Mapped[AuditRun] = relationship(back_populates="reviews")
