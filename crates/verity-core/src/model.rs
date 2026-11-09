//! What a read document looks like, and the strict parser that builds one from
//! untrusted JSON. Money is `Decimal` throughout; floats never touch an amount.
// Engineered by uncoalesced

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::{Map, Value};

/// Hard caps on untrusted input. Anything larger is rejected, not truncated,
/// so a payload can never be partially audited without the caller knowing.
pub const MAX_TEXT: usize = 512;
pub const MAX_LINE_ITEMS: usize = 1_000;
pub const MAX_HISTORY: usize = 100_000;

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct LineItem {
    pub name: String,
    pub quantity: Option<Decimal>,
    pub unit_price: Option<Decimal>,
    pub amount: Option<Decimal>,
}

impl LineItem {
    /// The row's contribution to the total, computed if it was not printed.
    pub fn resolved_amount(&self) -> Option<Decimal> {
        if let Some(a) = self.amount {
            return Some(a);
        }
        match (self.quantity, self.unit_price) {
            (Some(q), Some(u)) => Some(q * u),
            _ => self.unit_price,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Fields {
    pub vendor: Option<String>,
    pub date: Option<NaiveDate>,
    pub total: Option<Decimal>,
    pub subtotal: Option<Decimal>,
    pub tax: Option<Decimal>,
    pub line_items: Vec<LineItem>,
    pub signature_present: Option<bool>,
    pub confidence: f64,
    pub invoice_number: Option<String>,
    pub currency: Option<String>,
}

impl Default for Fields {
    fn default() -> Self {
        Fields {
            vendor: None,
            date: None,
            total: None,
            subtotal: None,
            tax: None,
            line_items: Vec::new(),
            signature_present: None,
            confidence: 1.0,
            invoice_number: None,
            currency: None,
        }
    }
}

impl Fields {
    /// Sum of the rows, or None when no row carried a usable amount.
    pub fn line_item_total(&self) -> Option<Decimal> {
        let mut out: Option<Decimal> = None;
        for a in self.line_items.iter().filter_map(LineItem::resolved_amount) {
            out = Some(match out {
                None => a,
                Some(s) => s + a,
            });
        }
        out
    }
}

/// Where a document came from. Every finding about it can be walked back here.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Source {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// A document already in the ledger, used by the cross-document controls.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Prior {
    pub document_id: i64,
    pub vendor: Option<String>,
    pub total: Option<Decimal>,
    pub date: Option<NaiveDate>,
    pub invoice_number: Option<String>,
    /// `normalize_vendor(vendor)`, computed once.
    #[serde(skip)]
    pub key: String,
}

impl Prior {
    pub fn new(
        document_id: i64,
        vendor: Option<String>,
        total: Option<Decimal>,
        date: Option<NaiveDate>,
        invoice_number: Option<String>,
    ) -> Self {
        let key = normalize_vendor(vendor.as_deref());
        Prior {
            document_id,
            vendor,
            total,
            date,
            invoice_number,
            key,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InputError(pub String);

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for InputError {}

fn err<T>(msg: impl Into<String>) -> Result<T, InputError> {
    Err(InputError(msg.into()))
}

/// Parse an amount. Accepts a JSON number or a plain decimal string
/// ("1234.56", "-10"). Thousands separators and currency symbols are rejected
/// rather than guessed at: a misread amount is worse than a refused one.
pub fn money(v: &Value, field: &str) -> Result<Option<Decimal>, InputError> {
    let text = match v {
        Value::Null => return Ok(None),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                return Ok(None);
            }
            t.to_string()
        }
        _ => return err(format!("{field}: expected a number or decimal string")),
    };
    if text.len() > 40 {
        return err(format!("{field}: amount too long"));
    }
    if text.contains(['e', 'E']) {
        return Decimal::from_scientific(&text)
            .map(Some)
            .map_err(|_| InputError(format!("{field}: not a decimal amount")));
    }
    Decimal::from_str_exact(&text).map(Some).map_err(|_| {
        InputError(format!(
            "{field}: not a decimal amount (use 1234.56, no separators or symbols)"
        ))
    })
}

pub fn date(v: &Value, field: &str) -> Result<Option<NaiveDate>, InputError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) if s.trim().is_empty() => Ok(None),
        Value::String(s) => NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
            .map(Some)
            .map_err(|_| InputError(format!("{field}: expected YYYY-MM-DD"))),
        _ => err(format!("{field}: expected YYYY-MM-DD string")),
    }
}

/// Untrusted free text: length-capped, control characters removed.
pub fn text(v: &Value, field: &str) -> Result<Option<String>, InputError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => {
            if s.chars().count() > MAX_TEXT {
                return err(format!("{field}: longer than {MAX_TEXT} characters"));
            }
            let clean: String = s.chars().filter(|c| !c.is_control()).collect();
            Ok(if clean.is_empty() { None } else { Some(clean) })
        }
        Value::Number(n) => Ok(Some(n.to_string())),
        _ => err(format!("{field}: expected a string")),
    }
}

fn boolean(v: &Value, field: &str) -> Result<Option<bool>, InputError> {
    match v {
        Value::Null => Ok(None),
        Value::Bool(b) => Ok(Some(*b)),
        _ => err(format!("{field}: expected true, false or null")),
    }
}

/// Reject any key not on the list. The echoed name is sanitised so an
/// attacker-chosen key cannot smuggle text into the error.
pub fn check_keys(
    obj: &Map<String, Value>,
    allowed: &[&str],
    what: &str,
) -> Result<(), InputError> {
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            let shown: String = k
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(40)
                .collect();
            return err(format!("{what}: unknown field '{shown}'"));
        }
    }
    Ok(())
}

pub const FIELD_KEYS: &[&str] = &[
    "vendor",
    "date",
    "total",
    "subtotal",
    "tax",
    "line_items",
    "signature_present",
    "confidence",
    "invoice_number",
    "currency",
];

pub fn parse_fields(v: &Value) -> Result<Fields, InputError> {
    let obj = v
        .as_object()
        .ok_or_else(|| InputError("fields: expected an object".into()))?;
    check_keys(obj, FIELD_KEYS, "fields")?;
    let g = |k: &str| obj.get(k).unwrap_or(&Value::Null);
    let mut items = Vec::new();
    match g("line_items") {
        Value::Null => {}
        Value::Array(list) => {
            if list.len() > MAX_LINE_ITEMS {
                return err(format!("line_items: more than {MAX_LINE_ITEMS} rows"));
            }
            for (i, it) in list.iter().enumerate() {
                let o = it
                    .as_object()
                    .ok_or_else(|| InputError(format!("line_items[{i}]: expected an object")))?;
                check_keys(
                    o,
                    &["name", "quantity", "unit_price", "amount"],
                    "line_items",
                )?;
                let gi = |k: &str| o.get(k).unwrap_or(&Value::Null);
                items.push(LineItem {
                    name: text(gi("name"), "line_items.name")?.unwrap_or_else(|| "Item".into()),
                    quantity: money(gi("quantity"), "line_items.quantity")?,
                    unit_price: money(gi("unit_price"), "line_items.unit_price")?,
                    amount: money(gi("amount"), "line_items.amount")?,
                });
            }
        }
        _ => return err("line_items: expected a list"),
    }
    let confidence = match g("confidence") {
        Value::Null => 1.0,
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        _ => f64::NAN,
    };
    if !(0.0..=1.0).contains(&confidence) {
        return err("confidence: expected a number between 0 and 1");
    }
    Ok(Fields {
        vendor: text(g("vendor"), "vendor")?,
        date: date(g("date"), "date")?,
        total: money(g("total"), "total")?,
        subtotal: money(g("subtotal"), "subtotal")?,
        tax: money(g("tax"), "tax")?,
        line_items: items,
        signature_present: boolean(g("signature_present"), "signature_present")?,
        confidence,
        invoice_number: text(g("invoice_number"), "invoice_number")?,
        currency: text(g("currency"), "currency")?,
    })
}

pub fn parse_prior(v: &Value, index: usize) -> Result<Prior, InputError> {
    let o = v
        .as_object()
        .ok_or_else(|| InputError(format!("history[{index}]: expected an object")))?;
    check_keys(
        o,
        &["document_id", "vendor", "total", "date", "invoice_number"],
        "history",
    )?;
    let g = |k: &str| o.get(k).unwrap_or(&Value::Null);
    let id = match g("document_id") {
        Value::Null => 1,
        Value::Number(n) => n
            .as_i64()
            .ok_or_else(|| InputError("history.document_id: expected an integer".into()))?,
        Value::String(s) => s
            .trim()
            .parse()
            .map_err(|_| InputError("history.document_id: expected an integer".into()))?,
        _ => return err("history.document_id: expected an integer"),
    };
    Ok(Prior::new(
        id,
        text(g("vendor"), "history.vendor")?,
        money(g("total"), "history.total")?,
        date(g("date"), "history.date")?,
        text(g("invoice_number"), "history.invoice_number")?,
    ))
}

/// Casefold and strip punctuation so "ACME Ltd." matches "acme ltd".
/// Mirrors `normalize_vendor` in the Python engine exactly.
pub fn normalize_vendor(name: Option<&str>) -> String {
    let Some(name) = name else {
        return String::new();
    };
    let lower = name.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut gap = false;
    for c in lower.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            if gap && !out.is_empty() {
                out.push(' ');
            }
            gap = false;
            out.push(c);
        } else {
            gap = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalizes_like_python() {
        assert_eq!(normalize_vendor(Some("ACME Ltd.")), "acme ltd");
        assert_eq!(normalize_vendor(Some("  --Foo,,Bar  ")), "foo bar");
        assert_eq!(normalize_vendor(Some("Café")), "caf");
        assert_eq!(normalize_vendor(None), "");
    }

    #[test]
    fn money_is_strict() {
        assert_eq!(
            money(&json!("1425.50"), "t").unwrap().unwrap().to_string(),
            "1425.50"
        );
        assert_eq!(
            money(&json!(1425.5), "t").unwrap().unwrap().to_string(),
            "1425.5"
        );
        assert_eq!(money(&json!(10), "t").unwrap().unwrap().to_string(), "10");
        assert!(money(&json!("$1,000"), "t").is_err());
        assert!(money(&json!(true), "t").is_err());
        assert_eq!(money(&json!(null), "t").unwrap(), None);
    }

    #[test]
    fn rejects_unknown_and_oversized() {
        assert!(parse_fields(&json!({"vendor": "a", "evil": 1})).is_err());
        assert!(parse_fields(&json!({"vendor": "x".repeat(MAX_TEXT + 1)})).is_err());
        assert!(parse_fields(&json!({"confidence": 2})).is_err());
    }

    #[test]
    fn strips_control_characters() {
        let f = parse_fields(&json!({"vendor": "Acme\u{0007}\nLtd"})).unwrap();
        assert_eq!(f.vendor.as_deref(), Some("AcmeLtd"));
    }
}
