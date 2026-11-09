//! Verity core: deterministic accounts-payable controls.
//!
//! No I/O, no network, no clock, no `unsafe`. Given the same document, the same
//! thresholds, the same history and the same audit date, the same findings come
//! out. That is what lets an approver say *why* an invoice was held.
// Engineered by uncoalesced
#![forbid(unsafe_code)]

pub mod batch;
pub mod forensic;
pub mod model;
pub mod policy;
pub mod rules;

pub use batch::{audit_batch, BatchReport, Document};
pub use model::{Fields, InputError, Prior, Source};
pub use policy::{Config, Policy, Severity, POLICIES};
pub use rules::{evaluate, Context, Finding, Outcome, Verdict};

use chrono::NaiveDate;
use serde_json::{Map, Value};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One audit request, parsed from untrusted JSON.
#[derive(Debug, Clone)]
pub struct Request {
    pub fields: Fields,
    /// `None` = caller supplied no history (cross-document controls not evaluated).
    pub history: Option<Vec<Prior>>,
    pub config: Config,
    pub today: Option<NaiveDate>,
    pub document_id: Option<i64>,
    pub filename: String,
    pub ingestion_status: String,
    pub reject_reason: Option<String>,
    pub source: Source,
}

const REQUEST_KEYS: &[&str] = &[
    "fields",
    "history",
    "config",
    "today",
    "document_id",
    "filename",
    "ingestion_status",
    "reject_reason",
    "source",
];

/// Accepts either `{"fields": {...}, "history": [...], ...}` or the v1.0
/// fixture shape where the fields sit at the top level next to `history`.
pub fn parse_request(v: &Value) -> Result<Request, InputError> {
    let obj = v
        .as_object()
        .ok_or_else(|| InputError("request: expected a JSON object".into()))?;
    let (fields_v, meta): (Value, Map<String, Value>) = if let Some(f) = obj.get("fields") {
        model::check_keys(obj, REQUEST_KEYS, "request")?;
        (f.clone(), obj.clone())
    } else {
        let mut fields = Map::new();
        let mut meta = Map::new();
        for (k, val) in obj {
            if model::FIELD_KEYS.contains(&k.as_str()) {
                fields.insert(k.clone(), val.clone());
            } else {
                meta.insert(k.clone(), val.clone());
            }
        }
        model::check_keys(&meta, REQUEST_KEYS, "request")?;
        (Value::Object(fields), meta)
    };
    let g = |k: &str| meta.get(k).unwrap_or(&Value::Null);
    let fields = model::parse_fields(&fields_v)?;
    let history = match g("history") {
        Value::Null => None,
        Value::Array(list) => {
            if list.len() > model::MAX_HISTORY {
                return Err(InputError(format!(
                    "history: more than {} entries",
                    model::MAX_HISTORY
                )));
            }
            Some(
                list.iter()
                    .enumerate()
                    .map(|(i, p)| model::parse_prior(p, i))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        _ => return Err(InputError("history: expected a list".into())),
    };
    let config = match g("config") {
        Value::Null => Config::default(),
        c => serde_json::from_value(c.clone()).map_err(|e| InputError(format!("config: {e}")))?,
    };
    let document_id = match g("document_id") {
        Value::Null => None,
        Value::Number(n) => Some(
            n.as_i64()
                .ok_or_else(|| InputError("document_id: expected an integer".into()))?,
        ),
        _ => return Err(InputError("document_id: expected an integer".into())),
    };
    let src = match g("source") {
        Value::Null => Source::default(),
        Value::Object(o) => {
            model::check_keys(o, &["file", "row", "sha256", "url"], "source")?;
            Source {
                file: model::text(o.get("file").unwrap_or(&Value::Null), "source.file")?,
                row: o.get("row").and_then(Value::as_u64),
                sha256: model::text(o.get("sha256").unwrap_or(&Value::Null), "source.sha256")?,
                url: model::text(o.get("url").unwrap_or(&Value::Null), "source.url")?,
            }
        }
        _ => return Err(InputError("source: expected an object".into())),
    };
    Ok(Request {
        fields,
        history,
        config,
        today: model::date(g("today"), "today")?,
        document_id,
        filename: model::text(g("filename"), "filename")?.unwrap_or_else(|| "document".into()),
        ingestion_status: model::text(g("ingestion_status"), "ingestion_status")?
            .unwrap_or_else(|| "accepted".into()),
        reject_reason: model::text(g("reject_reason"), "reject_reason")?,
        source: src,
    })
}

/// Audit one parsed request. `extra_history` (e.g. rows from Postgres) is
/// merged with any history in the request; if both are absent the
/// cross-document controls come back as `not_evaluated`.
pub fn audit(req: &Request, extra_history: Option<&[Prior]>, today: NaiveDate) -> Outcome {
    let mut all: Vec<&Prior> = Vec::new();
    let mut have = false;
    if let Some(h) = &req.history {
        have = true;
        all.extend(h.iter());
    }
    if let Some(h) = extra_history {
        have = true;
        all.extend(h.iter());
    }
    let ctx = Context {
        fields: &req.fields,
        config: &req.config,
        document_id: req.document_id,
        filename: &req.filename,
        ingestion_status: &req.ingestion_status,
        reject_reason: req.reject_reason.as_deref(),
        history: if have { Some(&all) } else { None },
        today: req.today.unwrap_or(today),
    };
    evaluate(&ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, 1).unwrap()
    }

    #[test]
    fn golden_arithmetic() {
        let r = parse_request(&json!({
            "vendor": "Apex Logistics Corp", "date": "2026-10-28", "total": "1675.00", "subtotal": "1500.00",
            "tax": "150.00", "signature_present": true, "confidence": 0.95,
            "line_items": [{"name": "a", "quantity": 1, "unit_price": "1000.00", "amount": "1000.00"},
                           {"name": "b", "quantity": 1, "unit_price": "500.00", "amount": "500.00"}]
        }))
        .unwrap();
        let o = audit(&r, None, day());
        assert_eq!(o.verdict, Verdict::Blocked);
        assert_eq!(o.findings[0].rule_id, "P-007");
        assert_eq!(o.findings[0].evidence["difference"], "25.00");
        assert_eq!(o.not_evaluated, rules::HISTORY_RULES);
    }

    #[test]
    fn golden_duplicate() {
        let r = parse_request(&json!({
            "vendor": "Acme Industrial Supplies Ltd", "date": "2026-10-25", "total": "1425.50",
            "history": [{"document_id": 1042, "vendor": "ACME Industrial Supplies Ltd.", "total": "1425.50", "date": "2026-10-25"}]
        }))
        .unwrap();
        let o = audit(&r, None, day());
        assert_eq!(o.verdict, Verdict::Blocked);
        assert!(o
            .findings
            .iter()
            .any(|f| f.rule_id == "P-002" && f.related == vec![1042]));
        assert!(o.not_evaluated.is_empty());
    }

    #[test]
    fn clean_with_history_passes() {
        let r = parse_request(&json!({
            "fields": {"vendor": "Northwind", "date": "2026-10-30", "total": "412.37", "subtotal": "374.88", "tax": "37.49"},
            "history": []
        }))
        .unwrap();
        let o = audit(&r, None, day());
        assert_eq!(o.verdict, Verdict::Pass, "{:?}", o.findings);
    }

    #[test]
    fn near_duplicate_and_reused_number() {
        let r = parse_request(&json!({
            "fields": {"vendor": "Northwind Traders Ltd", "date": "2026-10-30", "total": "412.37", "invoice_number": "NW-0042"},
            "history": [
                {"document_id": 7, "vendor": "Northwind Tradres Ltd", "total": "412.73", "date": "2026-10-28"},
                {"document_id": 8, "vendor": "Northwind Traders Ltd", "total": "99.00", "date": "2026-09-01", "invoice_number": "nw 0042"}
            ]
        }))
        .unwrap();
        let o = audit(&r, None, day());
        let ids: Vec<&str> = o.findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"P-016"), "{ids:?}");
        assert!(ids.contains(&"P-017"), "{ids:?}");
        assert_eq!(o.verdict, Verdict::Blocked);
    }

    #[test]
    fn sequential_invoice_numbers() {
        let r = parse_request(&json!({
            "fields": {"vendor": "Shell Co", "date": "2026-10-30", "total": "812.37", "invoice_number": "SC-103"},
            "history": [
                {"document_id": 1, "vendor": "Shell Co", "total": "700.10", "date": "2026-08-01", "invoice_number": "SC-101"},
                {"document_id": 2, "vendor": "Shell Co", "total": "640.55", "date": "2026-09-01", "invoice_number": "SC-102"}
            ]
        }))
        .unwrap();
        let o = audit(&r, None, day());
        let f = o
            .findings
            .iter()
            .find(|f| f.rule_id == "P-018")
            .expect("P-018");
        assert_eq!(f.related, vec![1, 2]);
    }

    #[test]
    fn currency_aware_round_amount() {
        let jpy = parse_request(&json!({"fields": {"vendor": "a", "date": "2026-10-30", "total": "1500", "currency": "JPY"}, "history": []})).unwrap();
        assert!(audit(&jpy, None, day())
            .findings
            .iter()
            .all(|f| f.rule_id != "P-010"));
        let usd = parse_request(&json!({"fields": {"vendor": "a", "date": "2026-10-30", "total": "1500"}, "history": []})).unwrap();
        assert!(audit(&usd, None, day())
            .findings
            .iter()
            .any(|f| f.rule_id == "P-010"));
    }

    #[test]
    fn unknown_top_level_key_rejected() {
        assert!(
            parse_request(&json!({"vendor": "a", "ignore_previous_instructions": true})).is_err()
        );
    }

    #[test]
    fn every_policy_has_text() {
        assert_eq!(POLICIES.len(), 18);
        assert!(POLICIES.iter().all(|p| p.text.len() > 60));
    }
}
