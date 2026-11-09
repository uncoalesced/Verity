//! Postgres ledger. Same tables the Python API uses (Alembic owns the schema;
//! run `alembic upgrade head`). Parameterised SQL only. Credentials come from
//! `DATABASE_URL` in the environment, never from arguments or logs.
// Engineered by uncoalesced

use verity_core::Prior;

#[cfg(feature = "postgres")]
mod pg {
    use super::*;
    use chrono::{NaiveDate, Utc};
    use rust_decimal::Decimal;
    use std::str::FromStr;
    use verity_core::{Fields, Outcome, Request};

    fn url() -> Option<String> {
        std::env::var("DATABASE_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .map(|u| {
                // SQLAlchemy URLs ("postgresql+psycopg://") -> libpq form.
                match u.split_once("://") {
                    Some((scheme, rest)) if scheme.starts_with("postgresql+") => {
                        format!("postgresql://{rest}")
                    }
                    _ => u,
                }
            })
    }

    fn connect() -> Result<Option<postgres::Client>, String> {
        let Some(u) = url() else { return Ok(None) };
        postgres::Client::connect(&u, postgres::NoTls)
            .map(Some)
            .map_err(|e| format!("database: {}", redact(&e.to_string())))
    }

    fn redact(s: &str) -> String {
        // Never echo a connection string that might carry a password.
        s.split_whitespace()
            .filter(|w| !w.contains("://") && !w.contains("password"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn available() -> bool {
        url().is_some()
    }

    /// Prior documents inside the lookback window. `None` when no database is
    /// configured, so callers can report `not_evaluated` honestly.
    pub fn history(cutoff: NaiveDate, exclude: Option<i64>) -> Result<Option<Vec<Prior>>, String> {
        let Some(mut c) = connect()? else {
            return Ok(None);
        };
        let with_inv =
            "SELECT document_id, vendor, total::text, date, invoice_number FROM extractions \
                        WHERE vendor IS NOT NULL AND date IS NOT NULL AND date >= $1";
        let without = "SELECT document_id, vendor, total::text, date, NULL::text FROM extractions \
                       WHERE vendor IS NOT NULL AND date IS NOT NULL AND date >= $1";
        let rows = match c.query(with_inv, &[&cutoff]) {
            Ok(r) => r,
            Err(_) => c
                .query(without, &[&cutoff])
                .map_err(|e| format!("database: {}", redact(&e.to_string())))?,
        };
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let id: i32 = r.get(0);
            if Some(id as i64) == exclude {
                continue;
            }
            let total: Option<String> = r.get(2);
            out.push(Prior::new(
                id as i64,
                r.get(1),
                total.and_then(|t| Decimal::from_str(&t).ok()),
                r.get(3),
                r.get(4),
            ));
        }
        Ok(Some(out))
    }

    fn money_text(d: Option<Decimal>) -> Option<String> {
        d.map(|d| d.to_string())
    }

    /// Record a document, its reading and the audit into the ledger. Returns
    /// (document_id, run_id).
    pub fn record(
        req: &Request,
        o: &Outcome,
        run_id: &str,
        ms: f64,
    ) -> Result<Option<(i64, String)>, String> {
        let Some(mut c) = connect()? else {
            return Ok(None);
        };
        let mut tx = c
            .transaction()
            .map_err(|e| format!("database: {}", redact(&e.to_string())))?;
        let f: &Fields = &req.fields;
        let src = req
            .source
            .file
            .clone()
            .unwrap_or_else(|| format!("mcp:{}", req.filename));
        let row = tx
            .query_one(
                "INSERT INTO documents (source_path, filename, format, ingestion_status, reject_reason) \
                 VALUES ($1, $2, 'fields', $3, $4) RETURNING id",
                &[&src, &req.filename, &req.ingestion_status, &req.reject_reason],
            )
            .map_err(|e| format!("database: {}", redact(&e.to_string())))?;
        let doc_id: i32 = row.get(0);
        let items = serde_json::to_value(&f.line_items).unwrap_or_default();
        let ins_ex = tx.execute(
            "INSERT INTO extractions (document_id, vendor, line_items, total, date, signature_present, confidence, invoice_number, currency, source_sha256) \
             VALUES ($1, $2, $3, $4::text::numeric, $5, $6, $7, $8, $9, $10)",
            &[&doc_id, &f.vendor, &items, &money_text(f.total), &f.date, &f.signature_present, &f.confidence, &f.invoice_number, &f.currency, &req.source.sha256],
        );
        if ins_ex.is_err() {
            // Pre-0004 schema: record without the v1.1 columns.
            tx.execute(
                "INSERT INTO extractions (document_id, vendor, line_items, total, date, signature_present, confidence) \
                 VALUES ($1, $2, $3, $4::text::numeric, $5, $6, $7)",
                &[&doc_id, &f.vendor, &items, &money_text(f.total), &f.date, &f.signature_present, &f.confidence],
            )
            .map_err(|e| format!("database: {}", redact(&e.to_string())))?;
        }
        let now = Utc::now();
        let fields_json = serde_json::to_value(f).unwrap_or_default();
        let cfg_json = serde_json::to_value(&req.config).unwrap_or_default();
        let worst = o.worst_severity.map(|s| s.as_str().to_string());
        let run = tx
            .query_one(
                "INSERT INTO audit_runs (run_id, document_id, filename, verdict, worst_severity, ingestion_status, reject_reason, fields, config, started_at, finished_at, duration_ms) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11) RETURNING id",
                &[&run_id, &doc_id, &req.filename, &o.verdict.as_str(), &worst, &req.ingestion_status, &req.reject_reason, &fields_json, &cfg_json, &now, &ms],
            )
            .map_err(|e| format!("database: {}", redact(&e.to_string())))?;
        let run_pk: i32 = run.get(0);
        for fd in &o.findings {
            let p = verity_core::policy::get(fd.rule_id);
            let ev = serde_json::Value::Object(fd.evidence.clone());
            tx.execute(
                "INSERT INTO findings (audit_run_id, rule_id, severity, message, evidence, policy_title, policy_text) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[&run_pk, &fd.rule_id, &fd.severity.as_str(), &fd.message, &ev, &p.map(|p| p.title), &p.map(|p| p.text)],
            )
            .map_err(|e| format!("database: {}", redact(&e.to_string())))?;
        }
        tx.commit()
            .map_err(|e| format!("database: {}", redact(&e.to_string())))?;
        Ok(Some((doc_id as i64, run_id.to_string())))
    }
}

#[cfg(feature = "postgres")]
pub use pg::{available, history, record};

#[cfg(not(feature = "postgres"))]
pub fn available() -> bool {
    false
}

#[cfg(not(feature = "postgres"))]
pub fn history(
    _cutoff: chrono::NaiveDate,
    _exclude: Option<i64>,
) -> Result<Option<Vec<Prior>>, String> {
    Ok(None)
}

#[cfg(not(feature = "postgres"))]
pub fn record(
    _r: &verity_core::Request,
    _o: &verity_core::Outcome,
    _id: &str,
    _ms: f64,
) -> Result<Option<(i64, String)>, String> {
    Ok(None)
}
