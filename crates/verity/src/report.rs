//! Output. Three shapes from one result: a compact text form for agents (no
//! document-supplied text, minimal tokens), a terminal form for people, and a
//! self-contained offline HTML report with drill-down provenance.
// Engineered by uncoalesced

use std::fmt::Write as _;
use verity_core::batch::{BatchReport, DocResult};
use verity_core::model::Source;
use verity_core::policy;
use verity_core::{Outcome, Severity, Verdict};

pub const PASS_HEX: &str = "#7FA650";
pub const REVIEW_HEX: &str = "#F2994A";
pub const BLOCKED_HEX: &str = "#EF4F6B";

fn upper(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "PASS",
        Verdict::Review => "REVIEW",
        Verdict::Blocked => "BLOCKED",
    }
}

/// Agent-facing. Built only from summaries (numbers, ids, dates) so a vendor
/// name written to look like an instruction never reaches the model here.
pub fn compact_single(o: &Outcome, run_id: Option<&str>) -> String {
    let mut s = String::with_capacity(256);
    let _ = write!(s, "{}", upper(o.verdict));
    if let Some(r) = run_id {
        let _ = write!(s, " run={r}");
    }
    let _ = writeln!(s, " findings={}", o.findings.len());
    for f in &o.findings {
        let _ = writeln!(s, "{} {}: {}", f.rule_id, f.severity.as_str(), f.summary);
    }
    if !o.not_evaluated.is_empty() {
        let _ = writeln!(
            s,
            "not_evaluated(no history): {}",
            o.not_evaluated.join(" ")
        );
    }
    s.truncate(s.trim_end().len());
    s
}

fn src_ref(src: &Source) -> String {
    match (&src.file, src.row) {
        (Some(f), Some(r)) => format!("{}:{r}", safe_token(f)),
        (Some(f), None) => safe_token(f),
        _ => String::new(),
    }
}

/// Filenames are caller-controlled; keep only a conservative character set.
pub fn safe_token(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._-/".contains(*c))
        .take(80)
        .collect()
}

pub fn compact_batch(r: &BatchReport, run_id: Option<&str>, limit: usize) -> String {
    let sm = &r.summary;
    let mut s = String::with_capacity(512);
    let _ = write!(
        s,
        "{} docs: {} pass, {} review, {} blocked",
        sm.documents, sm.pass, sm.review, sm.blocked
    );
    if let Some(id) = run_id {
        let _ = write!(s, " run={id}");
    }
    s.push('\n');
    if !sm.by_rule.is_empty() {
        let parts: Vec<String> = sm.by_rule.iter().map(|(k, v)| format!("{k}x{v}")).collect();
        let _ = writeln!(s, "rules: {}", parts.join(" "));
    }
    let b = &r.benford;
    match (&b.skipped, b.mad) {
        (Some(why), _) => {
            let _ = writeln!(s, "benford: not evaluated ({why})");
        }
        (None, Some(mad)) => {
            let _ = writeln!(
                s,
                "benford: {} (MAD {mad:.4}, n={})",
                b.conformity, b.tested
            );
        }
        _ => {}
    }
    let flagged: Vec<&DocResult> = r
        .documents
        .iter()
        .filter(|d| d.verdict != Verdict::Pass)
        .collect();
    for d in flagged.iter().take(limit) {
        let ids: Vec<&str> = d.findings.iter().map(|f| f.rule_id).collect();
        let sr = src_ref(&d.source);
        let _ = writeln!(
            s,
            "#{} {} {}{}",
            d.id,
            d.verdict.as_str(),
            ids.join(" "),
            if sr.is_empty() {
                String::new()
            } else {
                format!(" [{sr}]")
            }
        );
    }
    if flagged.len() > limit {
        let _ = writeln!(
            s,
            "+{} more flagged; use trace(run, doc) for any one",
            flagged.len() - limit
        );
    }
    s.truncate(s.trim_end().len());
    s
}

// --- terminal ---------------------------------------------------------------

pub struct Term {
    pub color: bool,
}

impl Term {
    fn paint(&self, hex: &str, t: &str) -> String {
        if !self.color {
            return t.to_string();
        }
        let n = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0xffffff);
        format!(
            "\x1b[38;2;{};{};{}m{t}\x1b[0m",
            n >> 16,
            (n >> 8) & 0xff,
            n & 0xff
        )
    }
    fn verdict(&self, v: Verdict) -> String {
        let (hex, mark) = match v {
            Verdict::Pass => (PASS_HEX, "■"),
            Verdict::Review => (REVIEW_HEX, "●"),
            Verdict::Blocked => (BLOCKED_HEX, "✕"),
        };
        self.paint(hex, &format!("{mark} {}", upper(v)))
    }
    fn sev(&self, s: Severity) -> String {
        let hex = match s {
            Severity::High => BLOCKED_HEX,
            Severity::Medium | Severity::Low => REVIEW_HEX,
            Severity::Info => PASS_HEX,
        };
        self.paint(hex, &s.as_str().to_uppercase())
    }

    pub fn single(&self, o: &Outcome, label: &str, explain: bool) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "{}  {}  ({} finding{})",
            self.verdict(o.verdict),
            label,
            o.findings.len(),
            if o.findings.len() == 1 { "" } else { "s" }
        );
        for f in &o.findings {
            let p = policy::get(f.rule_id);
            let _ = writeln!(
                s,
                "  {} {} {}",
                f.rule_id,
                self.sev(f.severity),
                p.map_or("", |p| p.title)
            );
            let _ = writeln!(s, "    {}", f.message);
            if explain {
                if let Some(p) = p {
                    let _ = writeln!(s, "    policy: {}", p.text);
                }
            }
        }
        if !o.not_evaluated.is_empty() {
            let _ = writeln!(
                s,
                "  not evaluated (no history supplied): {}",
                o.not_evaluated.join(" ")
            );
        }
        s
    }

    pub fn batch(&self, r: &BatchReport, limit: usize) -> String {
        let mut s = String::new();
        let sm = &r.summary;
        let _ = writeln!(
            s,
            "{} documents  {}  {}  {}",
            sm.documents,
            self.paint(PASS_HEX, &format!("■ {} pass", sm.pass)),
            self.paint(REVIEW_HEX, &format!("● {} review", sm.review)),
            self.paint(BLOCKED_HEX, &format!("✕ {} blocked", sm.blocked))
        );
        for (k, v) in &sm.by_rule {
            let _ = writeln!(
                s,
                "  {k} {:<34} {v}",
                policy::get(k).map_or("", |p| p.title)
            );
        }
        let b = &r.benford;
        match (&b.skipped, b.mad) {
            (Some(why), _) => {
                let _ = writeln!(s, "  Benford: not evaluated ({why})");
            }
            (None, Some(m)) => {
                let _ = writeln!(
                    s,
                    "  Benford: {} (MAD {m:.4}, n={})",
                    b.conformity, b.tested
                );
            }
            _ => {}
        }
        let flagged: Vec<&DocResult> = r
            .documents
            .iter()
            .filter(|d| d.verdict != Verdict::Pass)
            .collect();
        for d in flagged.iter().take(limit) {
            let ids: Vec<&str> = d.findings.iter().map(|f| f.rule_id).collect();
            let _ = writeln!(
                s,
                "  {} #{} {} {}",
                self.verdict(d.verdict),
                d.id,
                ids.join(" "),
                src_ref(&d.source)
            );
        }
        if flagged.len() > limit {
            let _ = writeln!(
                s,
                "  … {} more (use --report out.html or --json)",
                flagged.len() - limit
            );
        }
        s
    }
}

// --- HTML --------------------------------------------------------------------

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() => {}
            c => o.push(c),
        }
    }
    o
}

const CSS: &str = r#"
:root{--bg:#1f1f1f;--surface:#2b2b2b;--line:#3a3a3a;--text:#ecece6;--muted:#a3a39a;--pass:#7FA650;--review:#F2994A;--blocked:#EF4F6B}
@media (prefers-color-scheme:light){:root{--bg:#f6f5f0;--surface:#fff;--line:#e2e0d8;--text:#1d1d1b;--muted:#6b6b63}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 64px}h1{font:600 22px ui-monospace,SFMono-Regular,Menlo,monospace;margin:0 0 4px}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.tile b{display:block;font-size:24px}
.pass{color:var(--pass)}.review{color:var(--review)}.blocked{color:var(--blocked)}
details{background:var(--surface);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:0 14px}
details[open]{padding-bottom:12px}summary{cursor:pointer;padding:10px 0;list-style:none;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
summary::-webkit-details-marker{display:none}.f{border-top:1px solid var(--line);padding:10px 0 0;margin-top:10px}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);vertical-align:top}
a{color:inherit}.chip{font:12px ui-monospace,monospace;border:1px solid var(--line);border-radius:999px;padding:1px 8px}
blockquote{margin:6px 0;padding:6px 10px;border-left:3px solid var(--line);color:var(--muted)}
.bar{height:8px;border-radius:4px;background:var(--pass)}.bar.exp{background:var(--line)}
"#;

fn mark(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "■",
        Verdict::Review => "●",
        Verdict::Blocked => "✕",
    }
}

fn evidence_table(ev: &serde_json::Map<String, serde_json::Value>) -> String {
    let mut s = String::from("<table>");
    for (k, v) in ev {
        let val = match v {
            serde_json::Value::String(t) => t.clone(),
            other => other.to_string(),
        };
        let _ = write!(
            s,
            "<tr><th>{}</th><td class=mono>{}</td></tr>",
            esc(k),
            esc(&val)
        );
    }
    s.push_str("</table>");
    s
}

fn doc_block(
    d: &DocResult,
    by_id: &std::collections::HashMap<i64, &DocResult>,
    vendor: Option<&str>,
    total: Option<String>,
) -> String {
    let v = d.verdict;
    let mut s = String::new();
    let _ = write!(
        s,
        "<details id=\"doc-{id}\"{open}><summary><span class={vc}>{mk} {vu}</span><span class=mono>#{id}</span><span>{vendor}</span><span class=mono>{total}</span><span class=muted>{src}</span></summary>",
        id = d.id,
        open = if v == Verdict::Blocked { " open" } else { "" },
        vc = v.as_str(),
        mk = mark(v),
        vu = upper(v),
        vendor = esc(vendor.unwrap_or("(no supplier)")),
        total = esc(&total.unwrap_or_default()),
        src = esc(&src_ref(&d.source)),
    );
    if let Some(sha) = &d.source.sha256 {
        let _ = write!(
            s,
            "<div class=\"muted mono\">source sha256 {}</div>",
            esc(sha)
        );
    }
    for f in &d.findings {
        let p = policy::get(f.rule_id);
        let _ =
            write!(
            s,
            "<div class=f><span class=chip>{}</span> <b>{}</b> <span class={}>{}</span><p>{}</p>",
            esc(f.rule_id),
            esc(p.map_or("", |p| p.title)),
            if f.severity == Severity::High { "blocked" } else { "review" },
            f.severity.as_str(),
            esc(&f.message)
        );
        if !f.related.is_empty() {
            s.push_str("<p>Related: ");
            for r in &f.related {
                let label = by_id.get(r).map(|x| src_ref(&x.source)).unwrap_or_default();
                let _ = write!(
                    s,
                    "<a href=\"#doc-{r}\">#{r}</a> <span class=muted>{}</span> ",
                    esc(&label)
                );
            }
            s.push_str("</p>");
        }
        s.push_str(&evidence_table(&f.evidence));
        if let Some(p) = p {
            let _ = write!(s, "<blockquote>{}</blockquote>", esc(p.text));
        }
        s.push_str("</div>");
    }
    if !d.not_evaluated.is_empty() {
        let _ = write!(
            s,
            "<p class=muted>Not evaluated (no history): {}</p>",
            esc(&d.not_evaluated.join(" "))
        );
    }
    s.push_str("</details>");
    s
}

pub struct HtmlDoc<'a> {
    pub result: &'a DocResult,
    pub vendor: Option<&'a str>,
    pub total: Option<String>,
}

/// Self-contained: no scripts, no external requests, strict CSP. Opens offline.
pub fn html(title: &str, report: &BatchReport, docs: &[HtmlDoc]) -> String {
    let by_id: std::collections::HashMap<i64, &DocResult> =
        report.documents.iter().map(|d| (d.id, d)).collect();
    let sm = &report.summary;
    let mut s = String::with_capacity(4096 + docs.len() * 600);
    let _ = write!(
        s,
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">\
<title>Verity report</title><style>{CSS}</style></head><body><main><h1>Verity · {}</h1>\
<div class=muted>Verity {} · deterministic controls, no model in the verdict path · every finding links to its source row</div>",
        esc(title),
        verity_core::VERSION
    );
    let _ = write!(
        s,
        "<div class=tiles><div class=tile><b>{}</b>documents</div><div class=tile><b class=pass>{}</b>■ pass</div><div class=tile><b class=review>{}</b>● review</div><div class=tile><b class=blocked>{}</b>✕ blocked</div></div>",
        sm.documents, sm.pass, sm.review, sm.blocked
    );
    if !sm.by_rule.is_empty() {
        s.push_str(
            "<h2>Controls fired</h2><table><tr><th>Control</th><th>Title</th><th>Count</th></tr>",
        );
        for (k, v) in &sm.by_rule {
            let _ = write!(
                s,
                "<tr><td class=mono>{}</td><td>{}</td><td>{v}</td></tr>",
                esc(k),
                esc(policy::get(k).map_or("", |p| p.title))
            );
        }
        s.push_str("</table>");
    }
    let b = &report.benford;
    s.push_str("<h2>Benford first-digit test</h2>");
    match (&b.skipped, b.mad) {
        (Some(why), _) => {
            let _ = write!(s, "<p class=muted>Not evaluated: {}</p>", esc(why));
        }
        (None, Some(mad)) => {
            let _ = write!(s, "<p>{} · MAD {mad:.4} · n = {}</p><table><tr><th>Digit</th><th>Observed</th><th>Expected</th><th>z</th></tr>", esc(b.conformity), b.tested);
            for r in &b.digits {
                let _ = write!(
                    s,
                    "<tr><td>{}</td><td>{:.1}% <div class=bar style=\"width:{:.0}%\"></div></td><td>{:.1}% <div class=\"bar exp\" style=\"width:{:.0}%\"></div></td><td>{:.2}</td></tr>",
                    r.digit, r.observed * 100.0, r.observed * 300.0, r.expected * 100.0, r.expected * 300.0, r.z
                );
            }
            s.push_str("</table>");
            if let Some(f) = &b.finding {
                let _ = write!(s, "<p class=review>{}</p>", esc(&f.message));
            }
        }
        _ => {}
    }
    s.push_str("<h2>Documents</h2><p class=muted>Flagged first. Open any row for the findings, the computation, the policy quoted in full and links to related documents.</p>");
    let mut order: Vec<&HtmlDoc> = docs.iter().collect();
    order.sort_by_key(|d| match d.result.verdict {
        Verdict::Blocked => 0,
        Verdict::Review => 1,
        Verdict::Pass => 2,
    });
    for d in order {
        s.push_str(&doc_block(d.result, &by_id, d.vendor, d.total.clone()));
    }
    s.push_str("<p class=muted>Engineered by uncoalesced · Verity never approves payment; pass means no control objected.</p></main></body></html>");
    s
}

/// Neutralise spreadsheet formulas in exported text cells.
pub fn csv_safe(s: &str) -> String {
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html() {
        assert_eq!(
            esc("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
    }

    #[test]
    fn csv_formula_guard() {
        assert_eq!(csv_safe("=HYPERLINK(\"x\")"), "'=HYPERLINK(\"x\")");
        assert_eq!(csv_safe("Acme"), "Acme");
    }
}
