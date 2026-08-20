"""documents + extractions

Revision ID: 0001
Revises:
"""
import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Month 2 wires policy RAG onto this; the extension is cheap to have now.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "documents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_path", sa.Text(), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("format", sa.String(16), nullable=True),
        sa.Column("ingestion_status", sa.String(16), nullable=False),
        sa.Column("reject_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "extractions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("document_id", sa.Integer(), sa.ForeignKey("documents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vendor", sa.String(255), nullable=True),
        sa.Column("line_items", sa.JSON(), nullable=True),
        sa.Column("total", sa.Numeric(14, 2), nullable=True),
        sa.Column("date", sa.Date(), nullable=True),
        sa.Column("signature_present", sa.Boolean(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_extractions_document_id", "extractions", ["document_id"])


def downgrade() -> None:
    op.drop_index("ix_extractions_document_id", table_name="extractions")
    op.drop_table("extractions")
    op.drop_table("documents")
