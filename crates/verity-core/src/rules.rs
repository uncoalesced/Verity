//! The checks. Pure functions of (document, thresholds, history, date): no
//! clock, no I/O, no model. Same input, same findings, today and at the audit
//! six months from now.
//!
//! P-001..P-014 reproduce the v1.0 Python engine message-for-message; the
//! parity harness (`scripts/parity.py`) holds them to that.
// Engineered by uncoalesced

use crate::forensic::{invoice_key, jaro_winkler, numeric_suffix};
use crate::model::{normalize_vendor, Fields, Prior};
use crate::policy::{must, round_rule, rounding_unit, Config, Policy, Severity};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Review,
    Blocked,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Review => "review",
            Verdict::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    /// Human sentence. May quote document text (vendor names), so treat as
    /// untrusted when handing it to an agent; `summary` never does.
    pub message: String,
    /// Same finding with no document-supplied text in it. Safe to show an LLM.
    pub summary: String,
    pub evidence: Map<String, Value>,
    /// Other documents this finding is about, for provenance links.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<i64>,
}

/// Everything a rule may look at.
pub struct Context<'a> {
    pub fields: &'a Fields,
    pub config: &'a Config,
    pub document_id: Option<i64>,
    pub filename: &'a str,
    pub ingestion_status: &'a str,
    pub reject_reason: Option<&'a str>,
    /// `None` means no ledger was reachable: cross-document controls report
    /// `not_evaluated` instead of passing silently.
    pub history: Option<&'a [&'a Prior]>,
    pub today: NaiveDate,
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub verdict: Verdict,
    pub worst_severity: Option<Severity>,
    pub findings: Vec<Finding>,
    /// Controls that could not run (no history available). Never a pass.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_evaluated: Vec<&'static str>,
}

pub const HISTORY_RULES: &[&str] = &["P-002", "P-011", "P-016", "P-017", "P-018"];

fn finding(p: &'static Policy, message: String, summary: String, evidence: Value) -> Finding {
    finding_sev(p, p.severity, message, summary, evidence)
}

fn finding_sev(
    p: &'static Policy,
    sev: Severity,
    message: String,
    summary: String,
    evidence: Value,
) -> Finding {
    let evidence = match evidence {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    Finding {
        rule_id: p.id,
        severity: sev,
        message,
        summary,
        evidence,
        related: Vec::new(),
    }
}

fn m(v: Option<Decimal>) -> Value {
    v.map_or(Value::Null, |d| Value::String(d.to_string()))
}

fn pct0(x: f64) -> String {
    format!("{:.0}%", x * 100.0)
}

fn round4(x: f64) -> f64 {
    format!("{x:.4}").parse().unwrap_or(x)
}

fn iso(d: NaiveDate) -> String {
    d.format("%Y-%m-%d").to_string()
}

// --- P-001..P-014 -----------------------------------------------------------

fn intake_rejected(c: &Context) -> Option<Finding> {
    if c.ingestion_status == "accepted" {
        return None;
    }
    let reason = c.reject_reason.unwrap_or("unspecified reason");
    Some(finding(
        must("P-014"),
        format!("File was rejected at intake and never read: {reason}."),
        "file rejected at intake, never read".into(),
        json!({"filename": c.filename, "reject_reason": c.reject_reason}),
    ))
}

fn low_confidence(c: &Context) -> Option<Finding> {
    let conf = c.fields.confidence;
    let min = c.config.min_confidence;
    if conf >= min {
        return None;
    }
    Some(finding(
        must("P-013"),
        format!(
            "Read with {} confidence, below the {} threshold. Sent for manual review.",
            pct0(conf),
            pct0(min)
        ),
        format!("read confidence {} < {}", pct0(conf), pct0(min)),
        json!({"confidence": round4(conf), "threshold": min}),
    ))
}

fn unsubstantiated(c: &Context) -> Option<Finding> {
    let f = c.fields;
    let Some(total) = f.total else {
        return Some(finding(
            must("P-001"),
            "No amount could be read from the document, so the expense cannot be substantiated."
                .into(),
            "no amount readable".into(),
            json!({"total": null}),
        ));
    };
    let th = c.config.receipt_required_above;
    if total > th && f.vendor.is_none() && f.date.is_none() {
        return Some(finding(
            must("P-001"),
            format!("Amount {total} is above the {th} documentation threshold but the document shows neither a supplier nor a date."),
            format!("amount {total} > {th} with no supplier and no date"),
            json!({"total": total.to_string(), "threshold": th.to_string()}),
        ));
    }
    None
}

fn missing_vendor(c: &Context) -> Option<Finding> {
    if c.fields.vendor.is_some() {
        return None;
    }
    Some(finding(
        must("P-003"),
        "No supplier name could be read, so the document cannot be matched to a supplier record."
            .into(),
        "no supplier name".into(),
        json!({"vendor": null}),
    ))
}

fn missing_date(c: &Context) -> Option<Finding> {
    if c.fields.date.is_some() {
        return None;
    }
    Some(finding(
        must("P-004"),
        "No transaction date could be read, so the document cannot be assigned to a period.".into(),
        "no transaction date".into(),
        json!({"date": null}),
    ))
}

fn stale(c: &Context) -> Option<Finding> {
    if !c.config.stale_check_enabled {
        return None;
    }
    let date = c.fields.date?;
    if date > c.today {
        return None;
    }
    let age = (c.today - date).num_days();
    let window = c.config.stale_after_days;
    if age <= window {
        return None;
    }
    Some(finding(
        must("P-005"),
        format!("Document is {age} days old, past the {window}-day submission window."),
        format!("{age} days old > {window}-day window"),
        json!({"date": iso(date), "age_days": age, "window_days": window}),
    ))
}

fn future(c: &Context) -> Option<Finding> {
    let date = c.fields.date?;
    if date <= c.today {
        return None;
    }
    Some(finding(
        must("P-006"),
        format!(
            "Document is dated {}, which is in the future. The expense has not been incurred.",
            iso(date)
        ),
        format!("dated {} after audit date {}", iso(date), iso(c.today)),
        json!({"date": iso(date), "audited_on": iso(c.today)}),
    ))
}

fn arithmetic(c: &Context) -> Option<Finding> {
    let f = c.fields;
    let p = must("P-007");
    let tol = c
        .config
        .total_tolerance
        .max(rounding_unit(f.currency.as_deref()));
    let line_total = f.line_item_total();

    let (base, label) = if let Some(sub) = f.subtotal {
        if let Some(lt) = line_total {
            let gap = (sub - lt).abs();
            if gap > tol {
                return Some(finding(
                    p,
                    format!("Line items add up to {lt} but the document states a subtotal of {sub}, a difference of {gap}."),
                    format!("lines {lt} != subtotal {sub} (diff {gap})"),
                    json!({"line_item_total": lt.to_string(), "subtotal": sub.to_string(), "difference": gap.to_string()}),
                ));
            }
        }
        (sub, "subtotal")
    } else {
        (line_total?, "line items")
    };

    let total = f.total?;

    if let Some(tax) = f.tax {
        let expected = base + tax;
        let diff = (total - expected).abs();
        if diff > tol {
            return Some(finding(
                p,
                format!(
                    "The document states a {label} of {base} plus tax of {tax}, which comes to {expected}, but the stated total is {total} -- a difference of {diff}. The document does not agree with itself."
                ),
                format!("{label} {base} + tax {tax} = {expected} != total {total} (diff {diff})"),
                json!({
                    "base": base.to_string(), "base_label": label, "tax": tax.to_string(),
                    "expected_total": expected.to_string(), "total": total.to_string(), "difference": diff.to_string()
                }),
            ));
        }
        return None;
    }

    if base > total + tol {
        let msg = if label == "line items" {
            format!("Line items add up to {base}, more than the stated total of {total}. A total cannot be less than the sum of its own rows.")
        } else {
            format!("The document states a subtotal of {base}, more than its own total of {total}. A total cannot be less than the subtotal it is built from.")
        };
        return Some(finding(
            p,
            msg,
            format!("{label} {base} > total {total}"),
            json!({"line_item_total": m(line_total), "subtotal": m(f.subtotal), "total": total.to_string()}),
        ));
    }

    let ceiling = base * (Decimal::ONE + c.config.max_uplift_ratio) + tol;
    if total > ceiling {
        return Some(finding(
            p,
            format!("Stated total {total} exceeds the {label} ({base}) by more than tax and service could explain."),
            format!("total {total} > max explainable {ceiling} from {label} {base}"),
            json!({"base": base.to_string(), "base_label": label, "total": total.to_string(), "max_explainable": ceiling.to_string()}),
        ));
    }
    None
}

fn signature(c: &Context) -> Option<Finding> {
    let f = c.fields;
    let total = f.total?;
    if f.signature_present != Some(false) {
        return None;
    }
    let th = c.config.signature_required_above;
    if total <= th {
        return None;
    }
    Some(finding(
        must("P-008"),
        format!("Amount {total} is above the {th} signature threshold and no signature or stamp was found on the document."),
        format!("unsigned, amount {total} > {th}"),
        json!({"total": total.to_string(), "threshold": th.to_string()}),
    ))
}

fn approval_limit(c: &Context) -> Option<Finding> {
    if !c.config.approval_limit_enabled {
        return None;
    }
    let total = c.fields.total?;
    let limit = c.config.approval_limit;
    if total <= limit {
        return None;
    }
    Some(finding(
        must("P-009"),
        format!("Amount {total} exceeds the delegated approval limit of {limit} and needs sign-off at the next level of authority."),
        format!("amount {total} > approval limit {limit}"),
        json!({"total": total.to_string(), "limit": limit.to_string()}),
    ))
}

fn round_amount(c: &Context) -> Option<Finding> {
    let total = c.fields.total?;
    let currency = c.fields.currency.as_deref();
    let (floor, step) = round_rule(currency);
    let floor = c.config.round_floor.unwrap_or(floor);
    let step = c.config.round_step.unwrap_or(step);
    if total < floor || step.is_zero() || !(total % step).is_zero() {
        return None;
    }
    let mut ev = json!({"total": total.to_string(), "step": step.to_string()});
    if let Some(cur) = currency {
        ev["currency"] = Value::String(cur.to_string());
    }
    Some(finding(
        must("P-010"),
        format!("Amount {total} is exactly round, which is uncommon in genuine supplier billing."),
        format!("amount {total} is a multiple of {step}"),
        ev,
    ))
}

fn duplicate(c: &Context, hist: &[&Prior]) -> Option<Finding> {
    let f = c.fields;
    let (vendor, total, date) = (f.vendor.as_deref()?, f.total?, f.date?);
    let v = normalize_vendor(Some(vendor));
    for p in hist {
        if Some(p.document_id) == c.document_id {
            continue;
        }
        if p.key == v && p.total == Some(total) && p.date == Some(date) {
            let mut out = finding(
                must("P-002"),
                format!(
                    "Matches document #{} on supplier, amount ({total}) and date ({}). Held pending confirmation that the two are distinct.",
                    p.document_id,
                    iso(date)
                ),
                format!("same supplier, amount {total} and date {} as #{}", iso(date), p.document_id),
                json!({"matched_document_id": p.document_id, "vendor": vendor, "total": total.to_string(), "date": iso(date)}),
            );
            out.related.push(p.document_id);
            return Some(out);
        }
    }
    None
}

fn splitting(c: &Context, hist: &[&Prior]) -> Option<Finding> {
    let f = c.fields;
    let (vendor, total, date) = (f.vendor.as_deref()?, f.total?, f.date?);
    let limit = c.config.approval_limit;
    let floor = limit * c.config.split_proximity;
    if !(floor <= total && total <= limit) {
        return None;
    }
    let v = normalize_vendor(Some(vendor));
    let window = c.config.split_window_days;
    let sib: Vec<&Prior> = hist
        .iter()
        .filter(|p| {
            Some(p.document_id) != c.document_id
                && p.key == v
                && p.total.is_some_and(|t| floor <= t && t <= limit)
                && p.date
                    .is_some_and(|d| (d - date).num_days().abs() <= window)
        })
        .copied()
        .collect();
    if sib.is_empty() {
        return None;
    }
    let mut combined = total;
    for s in &sib {
        combined += s.total.unwrap_or_default();
    }
    let ids: Vec<i64> = sib.iter().map(|s| s.document_id).collect();
    let n = sib.len() + 1;
    let mut out = finding(
        must("P-011"),
        format!(
            "{n} documents from this supplier inside {window} days, each just below the {limit} approval limit, totalling {combined}. Reviewed together as one item."
        ),
        format!("{n} docs within {window} days just under limit {limit}, combined {combined}"),
        json!({"combined_total": combined.to_string(), "limit": limit.to_string(), "related_document_ids": ids, "window_days": window}),
    );
    out.related = ids;
    Some(out)
}

fn unapproved(c: &Context) -> Option<Finding> {
    let vendor = c.fields.vendor.as_deref()?;
    if c.config.approved_vendors.is_empty() {
        return None;
    }
    let v = normalize_vendor(Some(vendor));
    if c.config
        .approved_vendors
        .iter()
        .any(|a| normalize_vendor(Some(a)) == v)
    {
        return None;
    }
    Some(finding(
        must("P-012"),
        format!(
            "Supplier '{vendor}' is not on the approved supplier list. Held pending onboarding."
        ),
        "supplier not on approved list".into(),
        json!({"vendor": vendor}),
    ))
}

// --- v1.1 forensic, per document --------------------------------------------

fn near_duplicate(c: &Context, hist: &[&Prior]) -> Option<Finding> {
    let f = c.fields;
    let (vendor, total, date) = (f.vendor.as_deref()?, f.total?, f.date?);
    let v = normalize_vendor(Some(vendor));
    if v.is_empty() || total.is_zero() {
        return None;
    }
    let ratio = c.config.near_dup_amount_ratio;
    let window = c.config.near_dup_window_days;
    let min_sim = c.config.near_dup_vendor_similarity;
    let mut hits: Vec<(i64, f64, Decimal, NaiveDate)> = Vec::new();
    for p in hist {
        if Some(p.document_id) == c.document_id {
            continue;
        }
        let (Some(pt), Some(pd)) = (p.total, p.date) else {
            continue;
        };
        let pv = &p.key;
        if pv.is_empty() {
            continue;
        }
        let exact = *pv == v && pt == total && pd == date;
        if exact {
            continue; // P-002's job
        }
        if (pd - date).num_days().abs() > window {
            continue;
        }
        let big = if total.abs() > pt.abs() {
            total.abs()
        } else {
            pt.abs()
        };
        let tol = (big * ratio).max(Decimal::new(1, 2));
        if (pt - total).abs() > tol {
            continue;
        }
        let sim = if *pv == v { 1.0 } else { jaro_winkler(&v, pv) };
        if sim < min_sim {
            continue;
        }
        hits.push((p.document_id, sim, pt, pd));
    }
    let first = *hits.first()?;
    let ids: Vec<i64> = hits.iter().map(|h| h.0).collect();
    let more = if hits.len() > 1 {
        format!(" and {} other document(s)", hits.len() - 1)
    } else {
        String::new()
    };
    // Same supplier and the very same amount inside the window is a resubmitted
    // invoice with the date changed: held like an exact duplicate. Anything
    // fuzzier goes to review.
    let sev = if hits.iter().any(|h| h.1 >= 1.0 && h.2 == total) {
        Severity::High
    } else {
        must("P-016").severity
    };
    let mut out = finding_sev(
        must("P-016"),
        sev,
        format!(
            "Nearly matches document #{}{more}: amount {} vs {total}, dated {} vs {}, supplier name similarity {:.2}.",
            first.0, first.2, iso(first.3), iso(date), first.1
        ),
        format!("near-duplicate of #{} (amount {} vs {total}, {} vs {}, name sim {:.2})", first.0, first.2, iso(first.3), iso(date), first.1),
        json!({"matched_document_ids": ids, "amount_tolerance_ratio": ratio.to_string(), "window_days": window, "best_similarity": (first.1 * 100.0).round() / 100.0}),
    );
    out.related = ids;
    Some(out)
}

fn reused_invoice_number(c: &Context, hist: &[&Prior]) -> Option<Finding> {
    let f = c.fields;
    let key = invoice_key(f.invoice_number.as_deref()?)?;
    let v = normalize_vendor(f.vendor.as_deref());
    if v.is_empty() {
        return None;
    }
    let ids: Vec<i64> = hist
        .iter()
        .filter(|p| {
            Some(p.document_id) != c.document_id
                && p.key == v
                && p.invoice_number.as_deref().and_then(invoice_key).as_deref()
                    == Some(key.as_str())
        })
        .map(|p| p.document_id)
        .collect();
    if ids.is_empty() {
        return None;
    }
    let mut out = finding(
        must("P-017"),
        format!(
            "Invoice number {key} from this supplier also appears on document(s) {}.",
            fmt_ids(&ids)
        ),
        format!("invoice number reused on {}", fmt_ids(&ids)),
        json!({"invoice_number_key": key, "matched_document_ids": ids}),
    );
    out.related = ids;
    Some(out)
}

fn sequential_numbers(c: &Context, hist: &[&Prior]) -> Option<Finding> {
    let f = c.fields;
    let (prefix, n) = numeric_suffix(f.invoice_number.as_deref()?)?;
    let v = normalize_vendor(f.vendor.as_deref());
    if v.is_empty() {
        return None;
    }
    let mut seen: Vec<(u64, i64)> = hist
        .iter()
        .filter(|p| Some(p.document_id) != c.document_id && p.key == v)
        .filter_map(|p| {
            let (pp, pn) = numeric_suffix(p.invoice_number.as_deref()?)?;
            (pp == prefix).then_some((pn, p.document_id))
        })
        .collect();
    seen.sort_unstable();
    seen.dedup_by_key(|s| s.0);
    // Walk outward from n through consecutive numbers.
    let has = |x: u64| {
        seen.binary_search_by_key(&x, |s| s.0)
            .ok()
            .map(|i| seen[i].1)
    };
    let mut run: Vec<i64> = Vec::new();
    let mut lo = n;
    while lo > 0 {
        match has(lo - 1) {
            Some(id) => {
                run.push(id);
                lo -= 1;
            }
            None => break,
        }
    }
    let mut hi = n;
    while let Some(id) = has(hi + 1) {
        run.push(id);
        hi += 1;
    }
    let len = run.len() + 1;
    if len < c.config.sequential_min_run.max(2) {
        return None;
    }
    run.sort_unstable();
    let mut out = finding(
        must("P-018"),
        format!("This supplier's invoices to us run consecutively ({len} numbers, {lo} to {hi})."),
        format!("{len} consecutive invoice numbers {lo}..{hi}"),
        json!({"run_length": len, "first": lo, "last": hi, "related_document_ids": run}),
    );
    out.related = run;
    Some(out)
}

fn fmt_ids(ids: &[i64]) -> String {
    let shown: Vec<String> = ids.iter().take(5).map(|i| format!("#{i}")).collect();
    if ids.len() > 5 {
        format!("{} (+{} more)", shown.join(", "), ids.len() - 5)
    } else {
        shown.join(", ")
    }
}

// --- driver ------------------------------------------------------------------

type HistoryRule = fn(&Context, &[&Prior]) -> Option<Finding>;

/// Run every control against one document, worst finding first.
pub fn evaluate(c: &Context) -> Outcome {
    if let Some(r) = intake_rejected(c) {
        return outcome(vec![r], Vec::new());
    }
    let mut out: Vec<Finding> = Vec::with_capacity(4);
    let single: [fn(&Context) -> Option<Finding>; 10] = [
        low_confidence,
        unsubstantiated,
        missing_vendor,
        missing_date,
        stale,
        future,
        arithmetic,
        signature,
        approval_limit,
        round_amount,
    ];
    out.extend(single.iter().filter_map(|r| r(c)));
    let mut not_eval = Vec::new();
    match c.history {
        Some(h) => {
            let multi: [HistoryRule; 5] = [
                duplicate,
                splitting,
                near_duplicate,
                reused_invoice_number,
                sequential_numbers,
            ];
            out.extend(multi.iter().filter_map(|r| r(c, h)));
        }
        None => not_eval.extend_from_slice(HISTORY_RULES),
    }
    if let Some(f) = unapproved(c) {
        out.push(f);
    }
    outcome(out, not_eval)
}

fn outcome(mut findings: Vec<Finding>, not_evaluated: Vec<&'static str>) -> Outcome {
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.rule_id.cmp(b.rule_id)));
    Outcome {
        verdict: verdict(&findings),
        worst_severity: findings.iter().map(|f| f.severity).max(),
        findings,
        not_evaluated,
    }
}

/// `blocked` holds the payment, `review` needs a human, `pass` clears.
/// Verity never approves spend: the worst finding always wins.
pub fn verdict(findings: &[Finding]) -> Verdict {
    if findings.iter().any(|f| f.severity == Severity::High) {
        Verdict::Blocked
    } else if findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Medium | Severity::Low))
    {
        Verdict::Review
    } else {
        Verdict::Pass
    }
}
