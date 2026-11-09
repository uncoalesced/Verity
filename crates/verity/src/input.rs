//! Turning files on disk into audit requests: one JSON document, a JSON batch,
//! or a CSV mapped through a profile. Every row keeps its provenance.
// Engineered by uncoalesced

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use verity_core::model::{self, Fields, InputError, Prior, Source};
use verity_core::{parse_request, Config, Document, Request};

pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

#[allow(clippy::large_enum_variant)] // one value per run; boxing buys nothing
pub enum Loaded {
    Single(Box<Request>),
    Batch(Batch),
}

pub struct Batch {
    pub docs: Vec<Document>,
    pub ledger: Vec<Prior>,
    pub config: Config,
    pub today: Option<NaiveDate>,
    pub label: String,
}

/// A column can be named several ways across publishers; the first header that
/// matches (case- and space-insensitive) wins.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Col {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Columns {
    pub id: Option<Col>,
    pub vendor: Option<Col>,
    pub total: Option<Col>,
    pub date: Option<Col>,
    pub subtotal: Option<Col>,
    pub tax: Option<Col>,
    pub invoice_number: Option<Col>,
    pub currency: Option<Col>,
    pub confidence: Option<Col>,
    pub today: Option<Col>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // name/description/licence are documentation carried in the file
pub struct Profile {
    pub name: Option<String>,
    pub description: Option<String>,
    pub currency: Option<String>,
    pub today: Option<String>,
    #[serde(default)]
    pub config: Option<Value>,
    #[serde(default)]
    pub columns: Columns,
    #[serde(default)]
    pub date_formats: Vec<String>,
    pub licence: Option<String>,
}

pub fn read_profile(path: &Path) -> Result<Profile, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("profile {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("profile {}: {e}", path.display()))
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(hex(&Sha256::digest(&bytes)))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn check_size(path: &Path) -> Result<(), String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!(
            "{}: larger than {} MB",
            path.display(),
            MAX_FILE_BYTES / 1024 / 1024
        ));
    }
    Ok(())
}

pub fn load(path: &Path, profile: Option<&Profile>) -> Result<Loaded, String> {
    check_size(path)?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext == "csv" {
        return load_csv(path, profile.cloned().unwrap_or_default()).map(Loaded::Batch);
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v: Value = serde_json::from_str(&text)
        .map_err(|e| format!("{}: invalid JSON: {e}", path.display()))?;
    let label = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("input")
        .to_string();
    load_value(&v, &label, profile).map_err(|e| e.0)
}

/// JSON input: an object is one document unless it has `documents`; an array
/// is a batch.
pub fn load_value(v: &Value, label: &str, profile: Option<&Profile>) -> Result<Loaded, InputError> {
    let base_cfg = profile_config(profile)?;
    match v {
        Value::Array(list) => Ok(Loaded::Batch(batch_from(
            list, None, None, base_cfg, None, label,
        )?)),
        Value::Object(o) if o.contains_key("documents") => {
            model::check_keys(
                o,
                &[
                    "documents",
                    "history",
                    "config",
                    "today",
                    "dataset",
                    "licence",
                    "adjusted_receipts",
                    "description",
                ],
                "batch",
            )?;
            let list = o["documents"]
                .as_array()
                .ok_or_else(|| InputError("documents: expected a list".into()))?;
            let cfg = match o.get("config") {
                Some(c) if !c.is_null() => serde_json::from_value(c.clone())
                    .map_err(|e| InputError(format!("config: {e}")))?,
                _ => base_cfg,
            };
            let today =
                model::date(o.get("today").unwrap_or(&Value::Null), "today")?.or_else(|| {
                    profile
                        .and_then(|p| p.today.as_deref())
                        .and_then(|t| parse_date_any(t, &[]))
                });
            Ok(Loaded::Batch(batch_from(
                list,
                o.get("history"),
                today,
                cfg,
                None,
                label,
            )?))
        }
        _ => {
            let mut r = parse_request(v)?;
            if profile.is_some() {
                r.config = base_cfg;
            }
            Ok(Loaded::Single(Box::new(r)))
        }
    }
}

fn profile_config(p: Option<&Profile>) -> Result<Config, InputError> {
    match p.and_then(|p| p.config.clone()) {
        Some(c) => {
            serde_json::from_value(c).map_err(|e| InputError(format!("profile config: {e}")))
        }
        None => Ok(Config::default()),
    }
}

pub const MAX_BATCH: usize = 2_000_000;

pub fn batch_from(
    list: &[Value],
    history: Option<&Value>,
    today: Option<NaiveDate>,
    config: Config,
    file_sha: Option<&str>,
    label: &str,
) -> Result<Batch, InputError> {
    if list.len() > MAX_BATCH {
        return Err(InputError(format!(
            "batch: more than {MAX_BATCH} documents"
        )));
    }
    let mut docs = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        let o = item
            .as_object()
            .ok_or_else(|| InputError(format!("documents[{i}]: expected an object")))?;
        let mut fields = serde_json::Map::new();
        let mut id = (i + 1) as i64;
        let mut src = Source {
            file: Some(label.to_string()),
            row: Some(i as u64 + 1),
            sha256: file_sha.map(str::to_string),
            url: None,
        };
        let mut day = None;
        for (k, val) in o {
            match k.as_str() {
                "id" | "document_id" => {
                    id = val.as_i64().ok_or_else(|| {
                        InputError(format!("documents[{i}].id: expected an integer"))
                    })?
                }
                "today" => day = model::date(val, "today")?,
                "source" => {
                    if let Some(so) = val.as_object() {
                        model::check_keys(so, &["file", "row", "sha256", "url"], "source")?;
                        let t = |k: &str| model::text(so.get(k).unwrap_or(&Value::Null), "source");
                        src = Source {
                            file: t("file")?,
                            row: so.get("row").and_then(Value::as_u64),
                            sha256: t("sha256")?,
                            url: t("url")?,
                        };
                    }
                }
                "fields" => {
                    if let Some(fo) = val.as_object() {
                        fields.extend(fo.clone());
                    }
                }
                _ => {
                    fields.insert(k.clone(), val.clone());
                }
            }
        }
        let f = model::parse_fields(&Value::Object(fields))
            .map_err(|e| InputError(format!("documents[{i}]: {e}")))?;
        docs.push(Document {
            id,
            fields: f,
            source: src,
            today: day,
        });
    }
    // Provenance links and trace are keyed by id: a repeated id would point a
    // finding at the wrong document, so refuse the batch instead.
    let mut ids = std::collections::HashSet::with_capacity(docs.len());
    if let Some(d) = docs.iter().find(|d| !ids.insert(d.id)) {
        return Err(InputError(format!(
            "documents: id {} appears more than once",
            d.id
        )));
    }
    let ledger = match history {
        Some(Value::Array(h)) => h
            .iter()
            .enumerate()
            .map(|(i, p)| model::parse_prior(p, i))
            .collect::<Result<Vec<_>, _>>()?,
        _ => Vec::new(),
    };
    Ok(Batch {
        docs,
        ledger,
        config,
        today,
        label: label.to_string(),
    })
}

/// Amounts as published: "£25,000.00", "(1,200.50)", "-3,000". Thousands
/// separators and currency symbols are removed; parentheses mean negative.
/// Anything still not a plain decimal is reported as unreadable, not guessed.
pub fn lenient_money(raw: &str) -> Option<Decimal> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    let neg = t.starts_with('(') && t.ends_with(')');
    let cleaned: String = t
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    if cleaned.is_empty() || cleaned.matches('.').count() > 1 {
        return None;
    }
    let d: Decimal = cleaned.parse().ok()?;
    Some(if neg { -d.abs() } else { d })
}

fn parse_date_any(raw: &str, formats: &[String]) -> Option<NaiveDate> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    // Strip a trailing time component ("2024-01-31 00:00:00", "2024-01-31T00:00:00").
    let t = match t.find(['T', ' ']) {
        Some(i) if t[i + 1..].contains(':') => &t[..i],
        _ => t,
    };
    let defaults = [
        "%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%d-%b-%Y", "%d-%b-%y", "%d %b %Y",
    ];
    formats
        .iter()
        .map(String::as_str)
        .chain(defaults.iter().copied())
        .find_map(|f| NaiveDate::parse_from_str(t, f).ok())
}

fn norm_header(h: &str) -> String {
    h.trim()
        .trim_start_matches('\u{feff}')
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn many(names: &[&str]) -> Option<Col> {
    Some(Col::Many(names.iter().map(|s| s.to_string()).collect()))
}

/// Common header spellings, used for any column the profile does not name.
fn with_defaults(c: &Columns) -> Columns {
    Columns {
        id: c.id.clone().or_else(|| many(&["id", "document_id"])),
        vendor: c.vendor.clone().or_else(|| {
            many(&[
                "vendor",
                "vendor_name",
                "supplier",
                "supplier name",
                "payee",
                "merchant",
                "recipient_name",
            ])
        }),
        total: c.total.clone().or_else(|| {
            many(&[
                "total",
                "total_amount",
                "amount",
                "amount paid",
                "value",
                "gross amount",
            ])
        }),
        date: c.date.clone().or_else(|| {
            many(&[
                "date",
                "invoice_date",
                "payment date",
                "transaction date",
                "action_date",
            ])
        }),
        subtotal: c
            .subtotal
            .clone()
            .or_else(|| many(&["subtotal", "net amount"])),
        tax: c
            .tax
            .clone()
            .or_else(|| many(&["tax", "tax_amount", "vat"])),
        invoice_number: c
            .invoice_number
            .clone()
            .or_else(|| many(&["invoice_number", "invoice no", "invoice number"])),
        currency: c.currency.clone().or_else(|| many(&["currency"])),
        confidence: c
            .confidence
            .clone()
            .or_else(|| many(&["confidence", "ocr_confidence"])),
        today: c
            .today
            .clone()
            .or_else(|| many(&["audit_date", "submitted_date"])),
    }
}

pub fn load_csv(path: &Path, profile: Profile) -> Result<Batch, String> {
    let sha = sha256_file(path)?;
    let label = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("input.csv")
        .to_string();
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // Government CSVs are frequently Windows-1252; fall back byte-wise.
    let text = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => e.into_bytes().iter().map(|&b| b as char).collect(),
    };
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| format!("{label}: {e}"))?
        .iter()
        .map(norm_header)
        .collect();
    let index: HashMap<&str, usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| (h.as_str(), i))
        .collect();
    let find = |c: &Option<Col>| -> Option<usize> {
        let names: Vec<String> = match c.as_ref()? {
            Col::One(s) => vec![s.clone()],
            Col::Many(v) => v.clone(),
        };
        names
            .iter()
            .find_map(|n| index.get(norm_header(n).as_str()).copied())
    };
    let cols = with_defaults(&profile.columns);
    let cols = &cols;
    let (c_vendor, c_total, c_date) = (find(&cols.vendor), find(&cols.total), find(&cols.date));
    if c_total.is_none() {
        return Err(format!(
            "{label}: no amount column found (headers: {})",
            headers.join(" | ")
        ));
    }
    let (c_id, c_sub, c_tax, c_inv, c_cur, c_conf, c_today) = (
        find(&cols.id),
        find(&cols.subtotal),
        find(&cols.tax),
        find(&cols.invoice_number),
        find(&cols.currency),
        find(&cols.confidence),
        find(&cols.today),
    );
    let config = profile_config(Some(&profile)).map_err(|e| e.0)?;
    let today = profile
        .today
        .as_deref()
        .and_then(|t| parse_date_any(t, &[]));
    let mut docs = Vec::new();
    for (i, rec) in rdr.records().enumerate() {
        let rec = rec.map_err(|e| format!("{label} row {}: {e}", i + 2))?;
        let get = |c: Option<usize>| {
            c.and_then(|c| rec.get(c))
                .map(str::trim)
                .filter(|s| !s.is_empty())
        };
        if rec.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        if docs.len() >= MAX_BATCH {
            return Err(format!("{label}: more than {MAX_BATCH} rows"));
        }
        let cap = |s: Option<&str>| {
            s.map(|s| {
                s.chars()
                    .filter(|c| !c.is_control())
                    .take(model::MAX_TEXT)
                    .collect::<String>()
            })
        };
        let fields = Fields {
            vendor: cap(get(c_vendor)),
            date: get(c_date).and_then(|d| parse_date_any(d, &profile.date_formats)),
            total: get(c_total).and_then(lenient_money),
            subtotal: get(c_sub).and_then(lenient_money),
            tax: get(c_tax).and_then(lenient_money),
            line_items: Vec::new(),
            signature_present: None,
            confidence: get(c_conf)
                .and_then(|c| c.parse::<f64>().ok())
                .filter(|c| (0.0..=1.0).contains(c))
                .unwrap_or(1.0),
            invoice_number: cap(get(c_inv)),
            currency: cap(get(c_cur)).or_else(|| profile.currency.clone()),
        };
        let id = get(c_id)
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or((docs.len() + 1) as i64);
        let line = rec.position().map(|p| p.line() + 1).unwrap_or(i as u64 + 2); // 1-based file line, header is line 1
        docs.push(Document {
            id,
            fields,
            source: Source {
                file: Some(label.clone()),
                row: Some(line),
                sha256: Some(sha.clone()),
                url: None,
            },
            today: get(c_today).and_then(|d| parse_date_any(d, &profile.date_formats)),
        });
    }
    // Ids must be unique for provenance links to mean anything.
    let mut seen = std::collections::HashSet::new();
    if !docs.iter().all(|d| seen.insert(d.id)) {
        for (i, d) in docs.iter_mut().enumerate() {
            d.id = i as i64 + 1;
        }
    }
    Ok(Batch {
        docs,
        ledger: Vec::new(),
        config,
        today,
        label,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenient_money_cases() {
        assert_eq!(lenient_money("£25,000.00").unwrap().to_string(), "25000.00");
        assert_eq!(lenient_money("(1,200.50)").unwrap().to_string(), "-1200.50");
        assert_eq!(lenient_money(" 300 ").unwrap().to_string(), "300");
        assert!(lenient_money("1.2.3").is_none());
        assert!(lenient_money("n/a").is_none());
    }

    #[test]
    fn dates() {
        assert_eq!(
            parse_date_any("31/01/2024", &[]),
            NaiveDate::from_ymd_opt(2024, 1, 31)
        );
        assert_eq!(
            parse_date_any("2024-01-31 00:00:00", &[]),
            NaiveDate::from_ymd_opt(2024, 1, 31)
        );
        assert_eq!(
            parse_date_any("31-Jan-2024", &[]),
            NaiveDate::from_ymd_opt(2024, 1, 31)
        );
    }
}
