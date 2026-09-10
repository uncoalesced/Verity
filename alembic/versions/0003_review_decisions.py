"""review_decisions

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "review_decisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "audit_run_id",
            sa.Integer(),
            sa.ForeignKey("audit_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("reviewer", sa.String(255), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        # True when a reviewer released a payment the controls had blocked.
        # This is the column an internal auditor asks for by name.
        sa.Column("overrides_verdict", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_review_decisions_audit_run_id", "review_decisions", ["audit_run_id"])
    op.create_index("ix_review_decisions_decision", "review_decisions", ["decision"])


def downgrade() -> None:
    op.drop_table("review_decisions")
