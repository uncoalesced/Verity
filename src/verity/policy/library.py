"""The control library: the written policies Verity audits documents against.

Policies live here as data, not as scattered `if` statements, for one reason: a
finance team has to be able to read what the system enforced, quote it in an
audit file, and change a threshold without a developer. `rules.py` holds the
mechanics; this module holds the words and the numbers a controller cares about.

Every finding Verity emits cites a policy id from this list. Nothing is flagged
without a citation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

# Severity ladder. The audit verdict is derived from the worst finding, so the
# ordering here is the ordering of consequences.
INFO = "info"
LOW = "low"
MEDIUM = "medium"
HIGH = "high"

SEVERITY_ORDER = (INFO, LOW, MEDIUM, HIGH)


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


@dataclass(frozen=True)
class Policy:
    """One written control.

    `text` is the language a reviewer sees quoted on the finding, so it is
    phrased as policy, not as a code comment.
    """

    id: str
    title: str
    text: str
    severity: str
    category: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyConfig:
    """The numbers a finance team owns.

    Defaults are conservative mid-market values. Override per tenant rather than
    editing the library, so the library stays the same document for everyone.
    """

    receipt_required_above: Decimal = Decimal("75.00")
    signature_required_above: Decimal = Decimal("2500.00")
    approval_limit: Decimal = Decimal("10000.00")
    # Arithmetic tolerance: line items must reconcile to the stated total within
    # this absolute amount. Covers rounding, not fraud.
    total_tolerance: Decimal = Decimal("0.05")
    # How far above the sum of its own line items a total may sit before the gap
    # stops being explainable as tax, service charge or tip. 35% comfortably
    # covers a VAT-plus-service restaurant bill.
    max_uplift_ratio: Decimal = Decimal("0.35")
    stale_after_days: int = 90
    # Two invoices from one vendor inside this window, each just under the
    # approval limit, is the classic threshold-avoidance split.
    split_window_days: int = 14
    split_proximity: Decimal = Decimal("0.90")  # "just under" = >= 90% of the limit
    # Below this extraction confidence the document goes to a human regardless
    # of what the other rules say.
    min_confidence: float = 0.60
    # Empty means "no approved-supplier list configured", which disables P-012
    # rather than flagging every vendor on earth.
    approved_vendors: frozenset[str] = field(default_factory=frozenset)

    def as_dict(self) -> dict:
        """The thresholds as plain data -- what gets stored alongside a run so
        an old verdict stays explainable after the numbers here change."""
        return {
            "receipt_required_above": str(self.receipt_required_above),
            "signature_required_above": str(self.signature_required_above),
            "approval_limit": str(self.approval_limit),
            "total_tolerance": str(self.total_tolerance),
            "max_uplift_ratio": str(self.max_uplift_ratio),
            "stale_after_days": self.stale_after_days,
            "split_window_days": self.split_window_days,
            "split_proximity": str(self.split_proximity),
            "min_confidence": self.min_confidence,
            "approved_vendors": sorted(self.approved_vendors),
        }


POLICIES: tuple[Policy, ...] = (
    Policy(
        id="P-001",
        title="Supporting documentation required",
        text=(
            "Every expense above the documentation threshold must be supported by a legible "
            "receipt or supplier invoice showing the vendor, the date and the amount charged. "
            "Expenses submitted without readable supporting documentation are not reimbursable."
        ),
        severity=HIGH,
        category="documentation",
        tags=("receipt", "documentation", "substantiation", "missing", "amount"),
    ),
    Policy(
        id="P-002",
        title="Duplicate payment prevention",
        text=(
            "The same invoice must not be paid twice. An invoice matching a previously "
            "submitted document on vendor, amount and date is treated as a duplicate and "
            "held from payment until a reviewer confirms the two are genuinely distinct."
        ),
        severity=HIGH,
        category="payment-integrity",
        tags=("duplicate", "double payment", "invoice", "rebill", "vendor", "amount"),
    ),
    Policy(
        id="P-003",
        title="Supplier identification",
        text=(
            "The paying entity must be able to identify the supplier on the face of the "
            "document. A document with no legible vendor or merchant name cannot be matched "
            "to a supplier record and must not be posted to the ledger."
        ),
        severity=MEDIUM,
        category="documentation",
        tags=("vendor", "supplier", "merchant", "missing", "identification"),
    ),
    Policy(
        id="P-004",
        title="Transaction date required",
        text=(
            "Every supporting document must carry the date the goods or services were "
            "supplied. Undated documents cannot be assigned to an accounting period and "
            "must be returned to the submitter."
        ),
        severity=MEDIUM,
        category="documentation",
        tags=("date", "period", "missing", "cut-off"),
    ),
    Policy(
        id="P-005",
        title="Late submission",
        text=(
            "Expenses must be submitted within the submission window of the transaction "
            "date. Documents older than the window are flagged for review because they may "
            "belong to an accounting period that is already closed."
        ),
        severity=LOW,
        category="period-control",
        tags=("stale", "late", "old", "closed period", "cut-off", "date"),
    ),
    Policy(
        id="P-006",
        title="Future-dated documents",
        text=(
            "A supporting document dated in the future has not yet been incurred and cannot "
            "be reimbursed. Future dates most often indicate a transposed or fabricated date "
            "and are escalated rather than corrected silently."
        ),
        severity=HIGH,
        category="period-control",
        tags=("future", "date", "fabricated", "post-dated"),
    ),
    Policy(
        id="P-007",
        title="Arithmetic integrity",
        text=(
            "The line items on a document must reconcile to the stated total within "
            "tolerance. A total that exceeds the sum of its lines is the most common form of "
            "altered-document fraud and is escalated for manual inspection."
        ),
        severity=HIGH,
        category="document-integrity",
        tags=("total", "sum", "arithmetic", "altered", "mismatch", "line items"),
    ),
    Policy(
        id="P-008",
        title="Authorised signature",
        text=(
            "Documents above the signature threshold must carry a visible authorising "
            "signature or company stamp. Unsigned high-value documents are held pending "
            "evidence of authorisation."
        ),
        severity=MEDIUM,
        category="authorisation",
        tags=("signature", "stamp", "authorisation", "sign-off", "approval", "amount"),
    ),
    Policy(
        id="P-009",
        title="Delegated approval limit",
        text=(
            "Expenditure above the delegated approval limit requires sign-off at the next "
            "level of authority before payment is released. Verity does not approve such "
            "items; it routes them."
        ),
        severity=HIGH,
        category="authorisation",
        tags=("limit", "approval", "delegation", "authority", "threshold", "amount"),
    ),
    Policy(
        id="P-010",
        title="Round-amount anomaly",
        text=(
            "Amounts that are exactly round to a significant figure occur rarely in genuine "
            "supplier billing and frequently in invented expenses. A round amount alone is "
            "not misconduct; it is a signal that raises the priority of review."
        ),
        severity=LOW,
        category="anomaly",
        tags=("round", "anomaly", "pattern", "fabricated", "suspicious", "amount"),
    ),
    Policy(
        id="P-011",
        title="Threshold avoidance by splitting",
        text=(
            "Related expenditure must not be split across multiple documents to keep each "
            "part below an approval limit. Several submissions from one supplier inside a "
            "short window, each just below a limit, are reviewed together as one item."
        ),
        severity=HIGH,
        category="authorisation",
        tags=("split", "structuring", "threshold", "avoidance", "limit", "circumvention"),
    ),
    Policy(
        id="P-012",
        title="Approved supplier list",
        text=(
            "Payments may only be made to suppliers on the approved supplier list. A document "
            "naming a supplier that is not on the list is held until the supplier is "
            "onboarded and verified, which protects against invoice redirection fraud."
        ),
        severity=HIGH,
        category="vendor-control",
        tags=("vendor", "approved", "supplier list", "unknown", "onboarding", "redirection"),
    ),
    Policy(
        id="P-013",
        title="Low-confidence extraction",
        text=(
            "Where the system cannot read a document with sufficient confidence, the document "
            "is routed to a human reviewer. Verity does not guess: an unreadable document is "
            "reported as unreadable, never as compliant."
        ),
        severity=MEDIUM,
        category="assurance",
        tags=("confidence", "unreadable", "illegible", "quality", "manual review"),
    ),
    Policy(
        id="P-014",
        title="Intake rejection",
        text=(
            "A file that cannot be decoded, is blank, is password protected or is not a "
            "document format the system supports is rejected at intake and never scored. A "
            "rejected file is an open item, not a clean audit."
        ),
        severity=HIGH,
        category="assurance",
        tags=("rejected", "corrupt", "blank", "unreadable", "intake", "ingestion"),
    ),
)

BY_ID: dict[str, Policy] = {p.id: p for p in POLICIES}


def get(policy_id: str) -> Policy:
    """Look up one policy. Raises KeyError on an unknown id, which is a code bug."""
    return BY_ID[policy_id]
