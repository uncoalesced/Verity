"""v1.1: invoice numbers, currency and source provenance on extractions

Revision ID: 0004
Revises: 0003

Adds what the v1.1 controls and provenance links need: the supplier's invoice
number (P-017 reused numbers, P-018 sequential numbering), the currency
(currency-aware P-007 tolerance and P-010 round amounts) and the sha256 of the
source the reading came from. All nullable: every v1.0 row stays valid.
"""

import sqlalchemy as sa

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("extractions", sa.Column("invoice_number", sa.String(128), nullable=True))
    op.add_column("extractions", sa.Column("currency", sa.String(8), nullable=True))
    op.add_column("extractions", sa.Column("source_sha256", sa.String(64), nullable=True))
    op.create_index("ix_extractions_vendor_date", "extractions", ["vendor", "date"])


def downgrade() -> None:
    op.drop_index("ix_extractions_vendor_date", table_name="extractions")
    op.drop_column("extractions", "source_sha256")
    op.drop_column("extractions", "currency")
    op.drop_column("extractions", "invoice_number")
