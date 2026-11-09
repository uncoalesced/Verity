//! Auditing a population: every document against every other one in the
//! batch (plus any ledger supplied), then the population-level tests.
// Engineered by uncoalesced

use crate::forensic::{benford, Benford};
use crate::model::{Fields, Prior, Source};
use crate::policy::{Config, Severity};
use crate::rules::{evaluate, Context, Finding, Verdict};
use chrono::{Duration, NaiveDate};
use rust_decimal::Decimal;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone)]
pub struct Document {
    pub id: i64,
    pub fields: Fields,
    pub source: Source,
    /// Audit date for this document; falls back to the batch date.
    pub today: Option<NaiveDate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DocResult {
    pub id: i64,
    #[serde(skip_serializing_if = "is_empty_source")]
    pub source: Source,
    pub verdict: Verdict,
    pub worst_severity: Option<Severity>,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_evaluated: Vec<&'static str>,
}

fn is_empty_source(s: &Source) -> bool {
    s.file.is_none() && s.row.is_none() && s.sha256.is_none() && s.url.is_none()
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Summary {
    pub documents: usize,
    pub pass: usize,
    pub review: usize,
    pub blocked: usize,
    pub by_rule: BTreeMap<&'static str, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchReport {
    pub summary: Summary,
    pub benford: Benford,
    pub documents: Vec<DocResult>,
}

/// Audit every document. History for each one is: every other document in the
/// batch from the same supplier inside the lookback window, every other
/// document with a near amount (for fuzzy-name near-duplicates), and `ledger`.
/// With `history_available = false` and an empty batch neighbourhood, the
/// cross-document controls are reported as not evaluated.
pub fn audit_batch(
    docs: &[Document],
    ledger: &[Prior],
    cfg: &Config,
    today: NaiveDate,
) -> BatchReport {
    let priors: Vec<Prior> = docs
        .iter()
        .map(|d| {
            Prior::new(
                d.id,
                d.fields.vendor.clone(),
                d.fields.total,
                d.fields.date,
                d.fields.invoice_number.clone(),
            )
        })
        .chain(ledger.iter().cloned())
        .collect();

    let mut by_vendor: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, p) in priors.iter().enumerate() {
        if !p.key.is_empty() {
            by_vendor.entry(p.key.as_str()).or_default().push(i);
        }
    }
    let mut by_amount: Vec<(Decimal, usize)> = priors
        .iter()
        .enumerate()
        .filter_map(|(i, p)| p.total.map(|t| (t, i)))
        .collect();
    by_amount.sort_unstable_by_key(|x| x.0);

    let mut results = Vec::with_capacity(docs.len());
    let mut summary = Summary {
        documents: docs.len(),
        ..Default::default()
    };
    let mut hist: Vec<&Prior> = Vec::new();
    let mut seen: Vec<u32> = vec![u32::MAX; priors.len()];

    for (di, d) in docs.iter().enumerate() {
        let day = d.today.unwrap_or(today);
        // History is what was on file when this document arrived: anchor the
        // lookback to its own audit or transaction date, not the batch run date,
        // so a historical file is audited the way it would have been at the time.
        let anchor = d.today.or(d.fields.date).unwrap_or(today);
        let cutoff = anchor - Duration::days(cfg.lookback_days);
        hist.clear();
        let me = &priors[di];
        if let Some(group) = by_vendor.get(me.key.as_str()) {
            for &i in group {
                let p = &priors[i];
                if i != di && p.date.is_some_and(|dt| dt >= cutoff) {
                    hist.push(p);
                    seen[i] = di as u32;
                }
            }
        }
        if let Some(t) = d.fields.total {
            let tol =
                t.abs() * cfg.near_dup_amount_ratio * Decimal::new(11, 1) + Decimal::new(1, 2);
            let lo = by_amount.partition_point(|x| x.0 < t - tol);
            for &(a, i) in &by_amount[lo..] {
                if a > t + tol {
                    break;
                }
                if i != di && seen[i] != di as u32 && !priors[i].key.is_empty() {
                    hist.push(&priors[i]);
                    seen[i] = di as u32;
                }
            }
        }
        let ctx = Context {
            fields: &d.fields,
            config: cfg,
            document_id: Some(d.id),
            filename: d.source.file.as_deref().unwrap_or(""),
            ingestion_status: "accepted",
            reject_reason: None,
            history: Some(&hist),
            today: day,
        };
        let out = evaluate(&ctx);
        match out.verdict {
            Verdict::Pass => summary.pass += 1,
            Verdict::Review => summary.review += 1,
            Verdict::Blocked => summary.blocked += 1,
        }
        for f in &out.findings {
            *summary.by_rule.entry(f.rule_id).or_default() += 1;
        }
        results.push(DocResult {
            id: d.id,
            source: d.source.clone(),
            verdict: out.verdict,
            worst_severity: out.worst_severity,
            findings: out.findings,
            not_evaluated: out.not_evaluated,
        });
    }

    let amounts: Vec<(i64, Decimal)> = docs
        .iter()
        .filter_map(|d| d.fields.total.map(|t| (d.id, t)))
        .collect();
    let b = benford(&amounts, cfg);
    if let Some(f) = &b.finding {
        *summary.by_rule.entry(f.rule_id).or_default() += 1;
    }
    BatchReport {
        summary,
        benford: b,
        documents: results,
    }
}
