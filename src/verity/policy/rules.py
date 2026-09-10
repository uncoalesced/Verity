"""The checks themselves.

Every rule in `RULES` runs on every document. There is no retrieval step, no
model call and no sampling in this module: given the same document and the same
configured thresholds, the same findings come out, today and at the audit six
months from now. That determinism is the whole point -- an approver has to be
able to say *why* an invoice was held, and "the model felt uneasy" is not an
answer a finance function can put in a file.

Each finding names the policy it comes from and quotes the policy language.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from decimal import Decimal

from verity.extraction.schema import ExtractedFields
from verity.policy import library
from verity.policy.library import Policy, PolicyConfig, severity_rank

# Verdicts, in the language of an accounts-payable queue.
PASS = "pass"
REVIEW = "review"
BLOCKED = "blocked"

# A round total is only interesting above this amount; small round numbers are
# ordinary. ponytail: one currency-blind threshold. Make it per-currency once
# the corpus has more than one.
ROUND_AMOUNT_FLOOR = Decimal("500")
ROUND_AMOUNT_STEP = Decimal("100")

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalize_vendor(name: str | None) -> str:
    """Casefold and strip punctuation so 'ACME Ltd.' matches 'acme ltd'."""
    if not name:
        return ""
    return _NON_ALNUM.sub(" ", name.lower()).strip()


@dataclass(frozen=True)
class PriorDocument:
    """A document already in the ledger, used for the cross-document checks."""

    document_id: int
    vendor: str | None = None
    total: Decimal | None = None
    date: dt.date | None = None


@dataclass
class AuditContext:
    """Everything a rule is allowed to look at.

    Rules read this and nothing else -- no database handles, no network, no clock
    of their own. `today` is passed in so an audit can be re-run against the date
    it was originally performed and produce the same answer.
    """

    fields: ExtractedFields
    config: PolicyConfig = field(default_factory=PolicyConfig)
    document_id: int | None = None
    filename: str = ""
    ingestion_status: str = "accepted"
    reject_reason: str | None = None
    history: list[PriorDocument] = field(default_factory=list)
    today: dt.date = field(default_factory=dt.date.today)


@dataclass(frozen=True)
class Finding:
    """One thing wrong with one document, traced to one written policy."""

    rule_id: str
    severity: str
    message: str
    evidence: dict = field(default_factory=dict)
    policy_title: str = ""
    policy_text: str = ""

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
            "policy_title": self.policy_title,
            "policy_text": self.policy_text,
        }


def _finding(policy: Policy, message: str, evidence: dict | None = None, severity: str | None = None) -> Finding:
    return Finding(
        rule_id=policy.id,
        severity=severity or policy.severity,
        message=message,
        evidence=evidence or {},
        policy_title=policy.title,
        policy_text=policy.text,
    )


def _money(value: Decimal | None) -> str | None:
    return None if value is None else str(value)


# --- the rules -------------------------------------------------------------
# Each takes an AuditContext and returns a Finding or None. A rule that cannot
# tell -- because the field it needs was never read -- returns None and lets the
# missing-field rule speak instead. Silence here always means "not applicable",
# never "fine".


def rule_intake_rejected(ctx: AuditContext) -> Finding | None:
    """P-014. A file that never got read is an open item, not a clean audit."""
    if ctx.ingestion_status == "accepted":
        return None
    return _finding(
        library.get("P-014"),
        f"File was rejected at intake and never read: {ctx.reject_reason or 'unspecified reason'}.",
        {"filename": ctx.filename, "reject_reason": ctx.reject_reason},
    )


def rule_low_confidence(ctx: AuditContext) -> Finding | None:
    """P-013. Route to a human rather than reporting a guess as a result."""
    confidence = ctx.fields.confidence
    if confidence >= ctx.config.min_confidence:
        return None
    return _finding(
        library.get("P-013"),
        (
            f"Read with {confidence:.0%} confidence, below the {ctx.config.min_confidence:.0%} "
            "threshold. Sent for manual review."
        ),
        {"confidence": round(confidence, 4), "threshold": ctx.config.min_confidence},
    )


def rule_unsubstantiated_amount(ctx: AuditContext) -> Finding | None:
    """P-001. No readable amount, or a material amount with nothing to identify it."""
    f = ctx.fields
    if f.total is None:
        return _finding(
            library.get("P-001"),
            "No amount could be read from the document, so the expense cannot be substantiated.",
            {"total": None},
        )
    if f.total > ctx.config.receipt_required_above and not f.vendor and f.date is None:
        return _finding(
            library.get("P-001"),
            (
                f"Amount {f.total} is above the {ctx.config.receipt_required_above} documentation "
                "threshold but the document shows neither a supplier nor a date."
            ),
            {"total": _money(f.total), "threshold": _money(ctx.config.receipt_required_above)},
        )
    return None


def rule_missing_vendor(ctx: AuditContext) -> Finding | None:
    """P-003."""
    if ctx.fields.vendor:
        return None
    return _finding(
        library.get("P-003"),
        "No supplier name could be read, so the document cannot be matched to a supplier record.",
        {"vendor": None},
    )


def rule_missing_date(ctx: AuditContext) -> Finding | None:
    """P-004."""
    if ctx.fields.date is not None:
        return None
    return _finding(
        library.get("P-004"),
        "No transaction date could be read, so the document cannot be assigned to a period.",
        {"date": None},
    )


def rule_stale_document(ctx: AuditContext) -> Finding | None:
    """P-005."""
    date = ctx.fields.date
    if date is None or date > ctx.today:
        return None  # future dates belong to P-006
    age = (ctx.today - date).days
    if age <= ctx.config.stale_after_days:
        return None
    return _finding(
        library.get("P-005"),
        f"Document is {age} days old, past the {ctx.config.stale_after_days}-day submission window.",
        {"date": date.isoformat(), "age_days": age, "window_days": ctx.config.stale_after_days},
    )


def rule_future_dated(ctx: AuditContext) -> Finding | None:
    """P-006."""
    date = ctx.fields.date
    if date is None or date <= ctx.today:
        return None
    return _finding(
        library.get("P-006"),
        f"Document is dated {date.isoformat()}, which is in the future. The expense has not been incurred.",
        {"date": date.isoformat(), "audited_on": ctx.today.isoformat()},
    )


def rule_arithmetic_integrity(ctx: AuditContext) -> Finding | None:
    """P-007. Do the numbers printed on the document agree with each other?

    Two checks, in order of how much the document tells us:

    1. If the rows and a subtotal are both printed, the rows must reconcile to
       the subtotal.
    2. The total must then be explainable from that base. When the document
       also prints its tax, "explainable" is exact -- base + tax, to the cent.
       When it does not, the check falls back to a tolerance band: a total may
       sit above its base by tax and service (`max_uplift_ratio`) but never
       below it.

    The exact form matters more than it looks. An inflated total sitting inside
    a plausible tax band -- a 17% uplift where 12% tax was charged -- passes the
    band check and fails the arithmetic one. That is the single most common
    shape of invoice tampering, and it is only catchable against the tax the
    document itself claims.
    """
    f = ctx.fields
    policy = library.get("P-007")
    tolerance = ctx.config.total_tolerance
    line_total = f.line_item_total()

    # The base the total has to be explainable from: the subtotal when the
    # document prints one, otherwise the rows themselves.
    if f.subtotal is not None:
        if line_total is not None:
            gap = abs(f.subtotal - line_total)
            if gap > tolerance:
                return _finding(
                    policy,
                    (
                        f"Line items add up to {line_total} but the document states a subtotal of "
                        f"{f.subtotal}, a difference of {gap}."
                    ),
                    {
                        "line_item_total": _money(line_total),
                        "subtotal": _money(f.subtotal),
                        "difference": _money(gap),
                    },
                )
        base = f.subtotal
        base_label = "subtotal"
    elif line_total is not None:
        base = line_total
        base_label = "line items"
    else:
        return None  # nothing printed to check the total against

    if f.total is None:
        return None

    if f.tax is not None:
        expected = base + f.tax
        difference = abs(f.total - expected)
        if difference > tolerance:
            return _finding(
                policy,
                (
                    f"The document states a {base_label} of {base} plus tax of {f.tax}, which comes "
                    f"to {expected}, but the stated total is {f.total} -- a difference of "
                    f"{difference}. The document does not agree with itself."
                ),
                {
                    "base": _money(base),
                    "base_label": base_label,
                    "tax": _money(f.tax),
                    "expected_total": _money(expected),
                    "total": _money(f.total),
                    "difference": _money(difference),
                },
            )
        return None

    if base > f.total + tolerance:
        return _finding(
            policy,
            (
                f"Line items add up to {base}, more than the stated total of {f.total}. "
                "A total cannot be less than the sum of its own rows."
            )
            if base_label == "line items"
            else (
                f"The document states a subtotal of {base}, more than its own total of {f.total}. "
                "A total cannot be less than the subtotal it is built from."
            ),
            {"line_item_total": _money(line_total), "subtotal": _money(f.subtotal), "total": _money(f.total)},
        )

    ceiling = base * (Decimal("1") + ctx.config.max_uplift_ratio) + tolerance
    if f.total > ceiling:
        return _finding(
            policy,
            (
                f"Stated total {f.total} exceeds the {base_label} ({base}) by more than tax and "
                "service could explain."
            ),
            {
                "base": _money(base),
                "base_label": base_label,
                "total": _money(f.total),
                "max_explainable": _money(ceiling),
            },
        )
    return None


def rule_missing_signature(ctx: AuditContext) -> Finding | None:
    """P-008. Only fires when the page was actually checked for a signature."""
    f = ctx.fields
    if f.total is None or f.signature_present is not False:
        return None
    if f.total <= ctx.config.signature_required_above:
        return None
    return _finding(
        library.get("P-008"),
        (
            f"Amount {f.total} is above the {ctx.config.signature_required_above} signature "
            "threshold and no signature or stamp was found on the document."
        ),
        {"total": _money(f.total), "threshold": _money(ctx.config.signature_required_above)},
    )


def rule_over_approval_limit(ctx: AuditContext) -> Finding | None:
    """P-009. Verity does not approve spend; it routes it."""
    total = ctx.fields.total
    if total is None or total <= ctx.config.approval_limit:
        return None
    return _finding(
        library.get("P-009"),
        (
            f"Amount {total} exceeds the delegated approval limit of {ctx.config.approval_limit} "
            "and needs sign-off at the next level of authority."
        ),
        {"total": _money(total), "limit": _money(ctx.config.approval_limit)},
    )


def rule_round_amount(ctx: AuditContext) -> Finding | None:
    """P-010. A prompt to look, not an accusation."""
    total = ctx.fields.total
    if total is None or total < ROUND_AMOUNT_FLOOR:
        return None
    if total % ROUND_AMOUNT_STEP != 0:
        return None
    return _finding(
        library.get("P-010"),
        f"Amount {total} is exactly round, which is uncommon in genuine supplier billing.",
        {"total": _money(total), "step": str(ROUND_AMOUNT_STEP)},
    )


def rule_duplicate_payment(ctx: AuditContext) -> Finding | None:
    """P-002. Same supplier, same amount, same date as something already filed."""
    f = ctx.fields
    if not f.vendor or f.total is None or f.date is None:
        return None  # too little to claim a match; the missing-field rules cover it
    vendor = normalize_vendor(f.vendor)
    for prior in ctx.history:
        if prior.document_id == ctx.document_id:
            continue
        if normalize_vendor(prior.vendor) == vendor and prior.total == f.total and prior.date == f.date:
            return _finding(
                library.get("P-002"),
                (
                    f"Matches document #{prior.document_id} on supplier, amount ({f.total}) and date "
                    f"({f.date.isoformat()}). Held pending confirmation that the two are distinct."
                ),
                {
                    "matched_document_id": prior.document_id,
                    "vendor": f.vendor,
                    "total": _money(f.total),
                    "date": f.date.isoformat(),
                },
            )
    return None


def rule_threshold_splitting(ctx: AuditContext) -> Finding | None:
    """P-011. Several near-limit invoices from one supplier inside a short window."""
    f = ctx.fields
    if not f.vendor or f.total is None or f.date is None:
        return None
    limit = ctx.config.approval_limit
    floor = limit * ctx.config.split_proximity
    if not floor <= f.total <= limit:
        return None

    vendor = normalize_vendor(f.vendor)
    window = dt.timedelta(days=ctx.config.split_window_days)
    siblings = [
        prior
        for prior in ctx.history
        if prior.document_id != ctx.document_id
        and normalize_vendor(prior.vendor) == vendor
        and prior.total is not None
        and prior.date is not None
        and floor <= prior.total <= limit
        and abs(prior.date - f.date) <= window
    ]
    if not siblings:
        return None

    combined = f.total + sum((s.total for s in siblings), Decimal("0"))
    return _finding(
        library.get("P-011"),
        (
            f"{len(siblings) + 1} documents from this supplier inside {ctx.config.split_window_days} "
            f"days, each just below the {limit} approval limit, totalling {combined}. "
            "Reviewed together as one item."
        ),
        {
            "combined_total": _money(combined),
            "limit": _money(limit),
            "related_document_ids": [s.document_id for s in siblings],
            "window_days": ctx.config.split_window_days,
        },
    )


def rule_unapproved_vendor(ctx: AuditContext) -> Finding | None:
    """P-012. Skipped entirely when no approved-supplier list is configured."""
    f = ctx.fields
    if not ctx.config.approved_vendors or not f.vendor:
        return None
    approved = {normalize_vendor(v) for v in ctx.config.approved_vendors}
    if normalize_vendor(f.vendor) in approved:
        return None
    return _finding(
        library.get("P-012"),
        f"Supplier '{f.vendor}' is not on the approved supplier list. Held pending onboarding.",
        {"vendor": f.vendor},
    )


# Order here is the order rules are evaluated in; the report re-sorts by
# severity. Adding a rule means adding its policy to the library first.
RULES = (
    rule_low_confidence,
    rule_unsubstantiated_amount,
    rule_missing_vendor,
    rule_missing_date,
    rule_stale_document,
    rule_future_dated,
    rule_arithmetic_integrity,
    rule_missing_signature,
    rule_over_approval_limit,
    rule_round_amount,
    rule_duplicate_payment,
    rule_threshold_splitting,
    rule_unapproved_vendor,
)


def evaluate(ctx: AuditContext) -> list[Finding]:
    """Run every control against one document, worst finding first.

    A document rejected at intake short-circuits: nothing was read, so every
    other rule would only be commenting on empty fields.
    """
    rejected = rule_intake_rejected(ctx)
    if rejected is not None:
        return [rejected]

    findings = [f for f in (rule(ctx) for rule in RULES) if f is not None]
    findings.sort(key=lambda f: (-severity_rank(f.severity), f.rule_id))
    return findings


def verdict(findings: list[Finding]) -> str:
    """Turn findings into the decision an AP queue acts on.

    `blocked` holds the payment, `review` needs a human before release, `pass`
    clears. Nothing here approves spend, and the worst finding always wins.
    """
    if any(f.severity == library.HIGH for f in findings):
        return BLOCKED
    if any(f.severity in (library.MEDIUM, library.LOW) for f in findings):
        return REVIEW
    return PASS


def worst_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    return max((f.severity for f in findings), key=severity_rank)
