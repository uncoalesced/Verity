"""audit_runs + findings + trace_steps

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.String(32), nullable=False),
        sa.Column(
            "document_id",
            sa.Integer(),
            sa.ForeignKey("documents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("worst_severity", sa.String(16), nullable=True),
        sa.Column("ingestion_status", sa.String(16), nullable=False),
        sa.Column("reject_reason", sa.Text(), nullable=True),
        # The reading the decision was made on, and the thresholds in force at
        # the time. Together these are what make an old verdict reproducible.
        sa.Column("fields", sa.JSON(), nullable=True),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Float(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_audit_runs_run_id", "audit_runs", ["run_id"], unique=True)
    op.create_index("ix_audit_runs_document_id", "audit_runs", ["document_id"])
    op.create_index("ix_audit_runs_verdict", "audit_runs", ["verdict"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "audit_run_id",
            sa.Integer(),
            sa.ForeignKey("audit_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=True),
        # Copied, not referenced: a finding has to keep quoting the wording in
        # force when the document was held, even after the library moves on.
        sa.Column("policy_title", sa.String(255), nullable=True),
        sa.Column("policy_text", sa.Text(), nullable=True),
    )
    op.create_index("ix_findings_audit_run_id", "findings", ["audit_run_id"])
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])

    op.create_table(
        "trace_steps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "audit_run_id",
            sa.Integer(),
            sa.ForeignKey("audit_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("step_index", sa.Integer(), nullable=False),
        sa.Column("tool", sa.String(64), nullable=False),
        sa.Column("args", sa.JSON(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("ok", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Float(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
    )
    op.create_index("ix_trace_steps_audit_run_id", "trace_steps", ["audit_run_id"])


def downgrade() -> None:
    op.drop_table("trace_steps")
    op.drop_table("findings")
    op.drop_table("audit_runs")
