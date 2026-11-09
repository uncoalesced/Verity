//! The written controls. Words and numbers a controller owns, kept as data so
//! every finding can quote the policy it fired under.
// Engineered by uncoalesced

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Policy {
    pub id: &'static str,
    pub title: &'static str,
    pub text: &'static str,
    pub severity: Severity,
    pub category: &'static str,
}

macro_rules! p {
    ($id:literal, $title:literal, $sev:ident, $cat:literal, $text:literal) => {
        Policy {
            id: $id,
            title: $title,
            text: $text,
            severity: Severity::$sev,
            category: $cat,
        }
    };
}

/// P-001..P-014 are word-for-word the v1.0 library (`src/verity/policy/library.py`).
/// P-015..P-018 are the v1.1 forensic controls.
pub const POLICIES: &[Policy] = &[
    p!("P-001", "Supporting documentation required", High, "documentation",
       "Every expense above the documentation threshold must be supported by a legible receipt or supplier invoice showing the vendor, the date and the amount charged. Expenses submitted without readable supporting documentation are not reimbursable."),
    p!("P-002", "Duplicate payment prevention", High, "payment-integrity",
       "The same invoice must not be paid twice. An invoice matching a previously submitted document on vendor, amount and date is treated as a duplicate and held from payment until a reviewer confirms the two are genuinely distinct."),
    p!("P-003", "Supplier identification", Medium, "documentation",
       "The paying entity must be able to identify the supplier on the face of the document. A document with no legible vendor or merchant name cannot be matched to a supplier record and must not be posted to the ledger."),
    p!("P-004", "Transaction date required", Medium, "documentation",
       "Every supporting document must carry the date the goods or services were supplied. Undated documents cannot be assigned to an accounting period and must be returned to the submitter."),
    p!("P-005", "Late submission", Low, "period-control",
       "Expenses must be submitted within the submission window of the transaction date. Documents older than the window are flagged for review because they may belong to an accounting period that is already closed."),
    p!("P-006", "Future-dated documents", High, "period-control",
       "A supporting document dated in the future has not yet been incurred and cannot be reimbursed. Future dates most often indicate a transposed or fabricated date and are escalated rather than corrected silently."),
    p!("P-007", "Arithmetic integrity", High, "document-integrity",
       "The line items on a document must reconcile to the stated total within tolerance. A total that exceeds the sum of its lines is the most common form of altered-document fraud and is escalated for manual inspection."),
    p!("P-008", "Authorised signature", Medium, "authorisation",
       "Documents above the signature threshold must carry a visible authorising signature or company stamp. Unsigned high-value documents are held pending evidence of authorisation."),
    p!("P-009", "Delegated approval limit", High, "authorisation",
       "Expenditure above the delegated approval limit requires sign-off at the next level of authority before payment is released. Verity does not approve such items; it routes them."),
    p!("P-010", "Round-amount anomaly", Low, "anomaly",
       "Amounts that are exactly round to a significant figure occur rarely in genuine supplier billing and frequently in invented expenses. A round amount alone is not misconduct; it is a signal that raises the priority of review."),
    p!("P-011", "Threshold avoidance by splitting", High, "authorisation",
       "Related expenditure must not be split across multiple documents to keep each part below an approval limit. Several submissions from one supplier inside a short window, each just below a limit, are reviewed together as one item."),
    p!("P-012", "Approved supplier list", High, "vendor-control",
       "Payments may only be made to suppliers on the approved supplier list. A document naming a supplier that is not on the list is held until the supplier is onboarded and verified, which protects against invoice redirection fraud."),
    p!("P-013", "Low-confidence extraction", Medium, "assurance",
       "Where the system cannot read a document with sufficient confidence, the document is routed to a human reviewer. Verity does not guess: an unreadable document is reported as unreadable, never as compliant."),
    p!("P-014", "Intake rejection", High, "assurance",
       "A file that cannot be decoded, is blank, is password protected or is not a document format the system supports is rejected at intake and never scored. A rejected file is an open item, not a clean audit."),
    p!("P-015", "Benford first-digit conformity", Low, "forensic",
       "Across a population of payments, leading digits of naturally occurring amounts follow Benford's law. A population that departs from it beyond the nonconformity threshold is reviewed, starting with the digits that are most over-represented. Applies to populations, never to a single document."),
    p!("P-016", "Near-duplicate payment", Medium, "payment-integrity",
       "An invoice that nearly matches another (a supplier name differing only by spelling or punctuation, an amount within a fraction of a percent, dates within days) is reviewed alongside it before payment; the same supplier billing the same amount again within days is held as a duplicate. Near-duplicates are how exact-match duplicate checks are evaded."),
    p!("P-017", "Reused invoice number", High, "payment-integrity",
       "A supplier's invoice number identifies one invoice. The same number appearing on more than one document from the same supplier is held until the documents are reconciled."),
    p!("P-018", "Sequential invoice numbering", Low, "vendor-control",
       "A supplier whose invoices to us carry consecutive numbers may have no other customers, which is a marker of a shell or captive supplier. Raised for review, not as a finding of misconduct."),
];

pub fn get(id: &str) -> Option<&'static Policy> {
    POLICIES.iter().find(|p| p.id.eq_ignore_ascii_case(id))
}

pub(crate) fn must(id: &str) -> &'static Policy {
    get(id).expect("policy id compiled into the library")
}

/// The thresholds a finance team owns. Defaults match v1.0's `PolicyConfig`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub receipt_required_above: Decimal,
    pub signature_required_above: Decimal,
    pub approval_limit: Decimal,
    pub total_tolerance: Decimal,
    pub max_uplift_ratio: Decimal,
    pub stale_after_days: i64,
    pub split_window_days: i64,
    pub split_proximity: Decimal,
    pub min_confidence: f64,
    pub approved_vendors: Vec<String>,
    // v1.1
    /// Override the currency table for P-010.
    pub round_floor: Option<Decimal>,
    pub round_step: Option<Decimal>,
    /// Turn P-009 off for populations already filtered above the limit.
    pub approval_limit_enabled: bool,
    /// Turn P-005 off for historical datasets audited long after the fact.
    pub stale_check_enabled: bool,
    pub lookback_days: i64,
    pub near_dup_window_days: i64,
    pub near_dup_amount_ratio: Decimal,
    pub near_dup_vendor_similarity: f64,
    pub benford_min_n: usize,
    /// Reporting floor of the population (e.g. 25000 for UK "spend over £25k").
    /// Benford is only tested from the first power of ten at or above it.
    pub benford_floor: Option<Decimal>,
    pub sequential_min_run: usize,
}

fn d(s: &str) -> Decimal {
    Decimal::from_str(s).expect("literal decimal")
}

impl Default for Config {
    fn default() -> Self {
        Config {
            receipt_required_above: d("75.00"),
            signature_required_above: d("2500.00"),
            approval_limit: d("10000.00"),
            total_tolerance: d("0.05"),
            max_uplift_ratio: d("0.35"),
            stale_after_days: 90,
            split_window_days: 14,
            split_proximity: d("0.90"),
            min_confidence: 0.60,
            approved_vendors: Vec::new(),
            round_floor: None,
            round_step: None,
            approval_limit_enabled: true,
            stale_check_enabled: true,
            lookback_days: 180,
            near_dup_window_days: 7,
            near_dup_amount_ratio: d("0.005"),
            near_dup_vendor_similarity: 0.92,
            benford_min_n: 300,
            benford_floor: None,
            sequential_min_run: 3,
        }
    }
}

/// P-010 thresholds by currency: (floor, step). Unknown or absent currency uses
/// the v1.0 values (500, 100) so v1.0 verdicts are unchanged.
pub fn round_rule(currency: Option<&str>) -> (Decimal, Decimal) {
    let c = currency.map(|c| c.trim().to_ascii_uppercase());
    match c.as_deref() {
        Some("JPY") | Some("KRW") => (d("50000"), d("10000")),
        Some("INR") => (d("50000"), d("1000")),
        Some("IDR") | Some("VND") => (d("5000000"), d("100000")),
        _ => (d("500"), d("100")),
    }
}

/// Smallest amount a total is commonly rounded to in cash, by currency. P-007
/// never tolerates less than the configured tolerance, and never less than this
/// (an Indonesian receipt rounded to the nearest Rp 100 is not altered).
/// Absent currency keeps v1.0 behaviour.
pub fn rounding_unit(currency: Option<&str>) -> Decimal {
    let c = currency.map(|c| c.trim().to_ascii_uppercase());
    match c.as_deref() {
        Some("IDR") | Some("VND") => d("100"),
        Some("KRW") => d("10"),
        Some("JPY") => d("1"),
        _ => Decimal::ZERO,
    }
}
