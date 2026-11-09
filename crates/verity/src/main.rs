//! `verity` - deterministic accounts-payable auditor.
// Engineered by uncoalesced
#![forbid(unsafe_code)]

mod db;
mod input;
mod mcp;
mod report;

use chrono::{Duration, Local, NaiveDate};
use input::Loaded;
use serde_json::{json, Value};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;
use verity_core::batch::{BatchReport, DocResult, Summary};
use verity_core::forensic::Benford;
use verity_core::{audit, audit_batch, policy, Verdict};

const HELP: &str = "verity - deterministic accounts-payable auditor (Engineered by uncoalesced)

USAGE
  verity audit <file.json|file.csv> [options]   audit one document or a whole file
  verity explain [P-007]                        print a control's written policy (or list all)
  verity mcp [--http 127.0.0.1:8765]            run the MCP server (stdio by default)
  verity verify <MANIFEST.json>                 check a data snapshot's sha256 hashes (offline)
  verity --version

AUDIT OPTIONS
  --today YYYY-MM-DD   audit date (default: today)
  --profile FILE       column mapping + thresholds for CSV/JSON (see profiles/)
  --json               machine-readable output
  --report FILE.html   write an offline HTML report with drill-down provenance
  --csv FILE.csv       write one row per document (formula-safe)
  --explain            quote each control's policy text under its finding
  --limit N            flagged rows to print for a batch (default 40)
  --record             write a single audit to the Postgres ledger (DATABASE_URL)
  --no-color           plain output (also honours NO_COLOR)

EXIT CODES  0 pass · 1 review/blocked · 2 usage or input error";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("audit") => cmd_audit(&args[1..]),
        Some("explain") => cmd_explain(&args[1..]),
        Some("mcp") => cmd_mcp(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        Some("_parity") => cmd_parity(&args[1..]),
        Some("--version") | Some("-V") | Some("version") => {
            println!("verity {}", verity_core::VERSION);
            Ok(0)
        }
        Some("--help") | Some("-h") | Some("help") | None => {
            println!("{HELP}");
            Ok(0)
        }
        Some(other) => Err(format!(
            "unknown command '{}'; see verity --help",
            report::safe_token(other)
        )),
    };
    match r {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("verity: {e}");
            ExitCode::from(2)
        }
    }
}

struct Opts {
    file: Option<PathBuf>,
    today: Option<NaiveDate>,
    profile: Option<PathBuf>,
    json: bool,
    report: Option<PathBuf>,
    csv: Option<PathBuf>,
    explain: bool,
    limit: usize,
    record: bool,
    color: bool,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        file: None,
        today: None,
        profile: None,
        json: false,
        report: None,
        csv: None,
        explain: false,
        limit: 40,
        record: false,
        color: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match a.as_str() {
            "--today" => {
                o.today = Some(
                    NaiveDate::parse_from_str(&val("--today")?, "%Y-%m-%d")
                        .map_err(|_| "--today: expected YYYY-MM-DD")?,
                )
            }
            "--profile" => o.profile = Some(PathBuf::from(val("--profile")?)),
            "--report" => o.report = Some(PathBuf::from(val("--report")?)),
            "--csv" => o.csv = Some(PathBuf::from(val("--csv")?)),
            "--limit" => {
                o.limit = val("--limit")?
                    .parse()
                    .map_err(|_| "--limit: expected a number")?
            }
            "--json" => o.json = true,
            "--explain" => o.explain = true,
            "--record" => o.record = true,
            "--no-color" => o.color = false,
            s if s.starts_with("--") => {
                return Err(format!("unknown option {}", report::safe_token(s)))
            }
            s => {
                if o.file.is_some() {
                    return Err("one input file at a time".into());
                }
                o.file = Some(PathBuf::from(s));
            }
        }
    }
    Ok(o)
}

fn write_file(path: &Path, body: &str) -> Result<(), String> {
    std::fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn cmd_audit(args: &[String]) -> Result<u8, String> {
    let o = parse_opts(args)?;
    let file = o.file.clone().ok_or("audit: give a .json or .csv file")?;
    let profile = o.profile.as_deref().map(input::read_profile).transpose()?;
    let today = o.today.unwrap_or_else(|| Local::now().date_naive());
    let label = file
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("input")
        .to_string();
    let t0 = Instant::now();
    match input::load(&file, profile.as_ref())? {
        Loaded::Single(req) => {
            let ledger = if req.history.is_none() {
                let cut = req.today.unwrap_or(today) - Duration::days(req.config.lookback_days);
                db::history(cut, req.document_id)?
            } else {
                None
            };
            let out = audit(&req, ledger.as_deref(), today);
            let ms = t0.elapsed().as_secs_f64() * 1e3;
            if o.record {
                match db::record(
                    &req,
                    &out,
                    &format!(
                        "cli-{}-{}",
                        std::process::id(),
                        Local::now().timestamp_millis()
                    ),
                    ms,
                )? {
                    Some((doc, _)) => eprintln!("recorded as ledger document {doc}"),
                    None => return Err("--record: DATABASE_URL is not set".into()),
                }
            }
            if let Some(p) = &o.report {
                let dr = DocResult {
                    id: req.document_id.unwrap_or(1),
                    source: req.source.clone(),
                    verdict: out.verdict,
                    worst_severity: out.worst_severity,
                    findings: out.findings.clone(),
                    not_evaluated: out.not_evaluated.clone(),
                };
                let mut sm = Summary {
                    documents: 1,
                    ..Default::default()
                };
                match out.verdict {
                    Verdict::Pass => sm.pass = 1,
                    Verdict::Review => sm.review = 1,
                    Verdict::Blocked => sm.blocked = 1,
                }
                for f in &out.findings {
                    *sm.by_rule.entry(f.rule_id).or_default() += 1;
                }
                let rep = BatchReport {
                    summary: sm,
                    benford: Benford {
                        tested: 0,
                        tested_from: None,
                        mad: None,
                        conformity: "not_evaluated",
                        digits: vec![],
                        skipped: Some("single document".into()),
                        finding: None,
                    },
                    documents: vec![dr],
                };
                let docs = [report::HtmlDoc {
                    result: &rep.documents[0],
                    vendor: req.fields.vendor.as_deref(),
                    total: req.fields.total.map(|t| t.to_string()),
                }];
                write_file(p, &report::html(&label, &rep, &docs))?;
            }
            if o.json {
                let v = json!({"verity": verity_core::VERSION, "file": label, "verdict": out.verdict, "worst_severity": out.worst_severity,
                    "findings": out.findings, "not_evaluated": out.not_evaluated, "fields": req.fields, "elapsed_ms": ms});
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else {
                print!(
                    "{}",
                    report::Term { color: o.color }.single(&out, &label, o.explain)
                );
            }
            Ok(if out.verdict == Verdict::Pass { 0 } else { 1 })
        }
        Loaded::Batch(b) => {
            let loaded_ms = t0.elapsed().as_secs_f64() * 1e3;
            let day = o.today.or(b.today).unwrap_or(today);
            let t1 = Instant::now();
            let rep = audit_batch(&b.docs, &b.ledger, &b.config, day);
            let audit_ms = t1.elapsed().as_secs_f64() * 1e3;
            if let Some(p) = &o.report {
                let docs: Vec<report::HtmlDoc> = rep
                    .documents
                    .iter()
                    .zip(&b.docs)
                    .map(|(r, d)| report::HtmlDoc {
                        result: r,
                        vendor: d.fields.vendor.as_deref(),
                        total: d.fields.total.map(|t| t.to_string()),
                    })
                    .collect();
                write_file(p, &report::html(&b.label, &rep, &docs))?;
            }
            if let Some(p) = &o.csv {
                let mut w =
                    csv::Writer::from_path(p).map_err(|e| format!("{}: {e}", p.display()))?;
                let _ = w.write_record([
                    "id",
                    "verdict",
                    "controls",
                    "vendor",
                    "total",
                    "date",
                    "source_file",
                    "source_row",
                ]);
                for (r, d) in rep.documents.iter().zip(&b.docs) {
                    let ids: Vec<&str> = r.findings.iter().map(|f| f.rule_id).collect();
                    let _ = w.write_record([
                        r.id.to_string(),
                        r.verdict.as_str().to_string(),
                        ids.join(" "),
                        report::csv_safe(d.fields.vendor.as_deref().unwrap_or("")),
                        d.fields.total.map(|t| t.to_string()).unwrap_or_default(),
                        d.fields.date.map(|t| t.to_string()).unwrap_or_default(),
                        report::csv_safe(r.source.file.as_deref().unwrap_or("")),
                        r.source.row.map(|x| x.to_string()).unwrap_or_default(),
                    ]);
                }
                w.flush().map_err(|e| e.to_string())?;
            }
            if o.json {
                let mut v = serde_json::to_value(&rep).unwrap_or(Value::Null);
                v["verity"] = json!(verity_core::VERSION);
                v["file"] = json!(b.label);
                v["timing_ms"] = json!({"load": loaded_ms, "audit": audit_ms});
                println!("{}", serde_json::to_string(&v).unwrap_or_default());
            } else {
                print!("{}", report::Term { color: o.color }.batch(&rep, o.limit));
                eprintln!(
                    "audited {} documents in {:.1} ms (load {:.1} ms)",
                    rep.summary.documents, audit_ms, loaded_ms
                );
            }
            Ok(if rep.summary.review + rep.summary.blocked == 0 {
                0
            } else {
                1
            })
        }
    }
}

fn cmd_explain(args: &[String]) -> Result<u8, String> {
    match args.first() {
        Some(id) => {
            let p = policy::get(id)
                .ok_or_else(|| format!("unknown control {}", report::safe_token(id)))?;
            println!(
                "{} {}  [{} · {}]\n\n{}",
                p.id,
                p.title,
                p.severity.as_str(),
                p.category,
                p.text
            );
        }
        None => {
            for p in policy::POLICIES {
                println!("{} {:<36} {}", p.id, p.title, p.severity.as_str());
            }
        }
    }
    Ok(0)
}

fn cmd_mcp(args: &[String]) -> Result<u8, String> {
    match args {
        [] => mcp::serve_stdio().map(|_| 0),
        [flag, rest @ ..] if flag == "--http" => {
            #[cfg(feature = "http")]
            {
                let addr = rest.first().map(String::as_str).unwrap_or("127.0.0.1:8765");
                mcp::serve_http(addr).map(|_| 0)
            }
            #[cfg(not(feature = "http"))]
            {
                let _ = rest;
                Err("this build has no HTTP support".into())
            }
        }
        _ => Err("usage: verity mcp [--http ADDR]".into()),
    }
}

/// Offline integrity check of a data snapshot: every file listed must exist and
/// hash to the recorded sha256. No network.
fn cmd_verify(args: &[String]) -> Result<u8, String> {
    let path = PathBuf::from(args.first().ok_or("verify: give the MANIFEST.json path")?);
    let base = path.parent().unwrap_or(Path::new("."));
    let m: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?,
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;
    let files = m
        .get("files")
        .and_then(Value::as_array)
        .ok_or("manifest: no files list")?;
    let mut bad = 0;
    for f in files {
        let name = f
            .get("path")
            .and_then(Value::as_str)
            .ok_or("manifest: file without path")?;
        if name.contains("..") || Path::new(name).is_absolute() {
            return Err(format!(
                "manifest: refusing path {}",
                report::safe_token(name)
            ));
        }
        let want = f.get("sha256").and_then(Value::as_str).unwrap_or("");
        let got = input::sha256_file(&base.join(name)).unwrap_or_else(|e| format!("missing ({e})"));
        if got != want {
            bad += 1;
            println!("MISMATCH {name}: {got}");
        }
    }
    if bad == 0 {
        println!("manifest ok: {} files verified", files.len());
        Ok(0)
    } else {
        Err(format!("{bad} file(s) failed verification"))
    }
}

/// Hidden: evaluate a JSON array of requests exactly as given (used by
/// scripts/parity.py to hold the Rust engine to the Python one).
fn cmd_parity(args: &[String]) -> Result<u8, String> {
    let path = args.first().ok_or("_parity: file")?;
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let list = v.as_array().ok_or("_parity: expected an array")?;
    let fallback = Local::now().date_naive();
    let mut out = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        let req = verity_core::parse_request(item).map_err(|e| format!("case {i}: {e}"))?;
        let o = audit(&req, None, fallback);
        out.push(json!({"verdict": o.verdict, "findings": o.findings.iter().map(|f| json!({
            "rule_id": f.rule_id, "severity": f.severity, "message": f.message, "evidence": f.evidence})).collect::<Vec<_>>()}));
    }
    println!("{}", Value::Array(out));
    Ok(0)
}
