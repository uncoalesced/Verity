//! Forensic helpers: string similarity for near-duplicates, invoice-number
//! normalisation, and Benford first-digit testing over a population.
// Engineered by uncoalesced

use crate::policy::{must, Config, Severity};
use crate::rules::Finding;
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::json;

/// Jaro-Winkler similarity in [0, 1]. Used on already-normalised vendor names.
pub fn jaro_winkler(a: &str, b: &str) -> f64 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() || b.is_empty() {
        return if a == b { 1.0 } else { 0.0 };
    }
    let range = (a.len().max(b.len()) / 2).saturating_sub(1);
    let mut am = vec![false; a.len()];
    let mut bm = vec![false; b.len()];
    let mut matches = 0usize;
    for i in 0..a.len() {
        let lo = i.saturating_sub(range);
        let hi = (i + range + 1).min(b.len());
        for j in lo..hi {
            if !bm[j] && a[i] == b[j] {
                am[i] = true;
                bm[j] = true;
                matches += 1;
                break;
            }
        }
    }
    if matches == 0 {
        return 0.0;
    }
    let (mut t, mut k) = (0usize, 0usize);
    for i in 0..a.len() {
        if am[i] {
            while !bm[k] {
                k += 1;
            }
            if a[i] != b[k] {
                t += 1;
            }
            k += 1;
        }
    }
    let mf = matches as f64;
    let jaro = (mf / a.len() as f64 + mf / b.len() as f64 + (mf - t as f64 / 2.0) / mf) / 3.0;
    let prefix = a
        .iter()
        .zip(b.iter())
        .take(4)
        .take_while(|(x, y)| x == y)
        .count();
    jaro + prefix as f64 * 0.1 * (1.0 - jaro)
}

/// Comparable form of an invoice number: uppercase alphanumerics only, leading
/// zeros of the numeric tail kept (INV-0042 and INV42 are different documents).
pub fn invoice_key(raw: &str) -> Option<String> {
    let k: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (!k.is_empty()).then_some(k)
}

/// Split an invoice number into (prefix, numeric tail): "INV-1043" -> ("INV", 1043).
pub fn numeric_suffix(raw: &str) -> Option<(String, u64)> {
    let k = invoice_key(raw)?;
    let split = k.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    let digits = &k[split..];
    if digits.is_empty() || digits.len() > 18 {
        return None;
    }
    Some((k[..split].to_string(), digits.parse().ok()?))
}

fn first_digit(d: Decimal) -> Option<u8> {
    let s = d.abs().to_string();
    s.bytes()
        .find(|b| (b'1'..=b'9').contains(b))
        .map(|b| b - b'0')
}

#[derive(Debug, Clone, Serialize)]
pub struct DigitRow {
    pub digit: u8,
    pub count: usize,
    pub observed: f64,
    pub expected: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Benford {
    pub tested: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tested_from: Option<String>,
    pub mad: Option<f64>,
    /// Nigrini (2012) first-digit bands: close / acceptable / marginal / nonconformity.
    pub conformity: &'static str,
    pub digits: Vec<DigitRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding: Option<Finding>,
}

fn r4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

/// Benford first-digit test over `(document_id, amount)` pairs.
///
/// Truncated populations (a published "spend over £25k" list) distort the
/// leading-digit distribution, so with `benford_floor` set only amounts from
/// the first power of ten at or above the floor are tested.
pub fn benford(items: &[(i64, Decimal)], cfg: &Config) -> Benford {
    let mut from = Decimal::TEN;
    if let Some(floor) = cfg.benford_floor {
        while from < floor {
            from *= Decimal::TEN;
        }
    }
    let pop: Vec<(i64, Decimal, u8)> = items
        .iter()
        .filter(|(_, a)| a.abs() >= from)
        .filter_map(|(id, a)| first_digit(*a).map(|d| (*id, a.abs(), d)))
        .collect();
    let n = pop.len();
    let tested_from = cfg.benford_floor.map(|_| from.to_string());
    let skip = |why: String| Benford {
        tested: n,
        tested_from: tested_from.clone(),
        mad: None,
        conformity: "not_evaluated",
        digits: Vec::new(),
        skipped: Some(why),
        finding: None,
    };
    if n < cfg.benford_min_n {
        return skip(format!(
            "{n} amounts at or above {from}; needs at least {}",
            cfg.benford_min_n
        ));
    }
    let (lo, hi) = pop
        .iter()
        .fold((pop[0].1, pop[0].1), |(l, h), x| (l.min(x.1), h.max(x.1)));
    if hi < lo * Decimal::ONE_HUNDRED {
        return skip(format!(
            "amounts span less than two orders of magnitude ({lo} to {hi})"
        ));
    }
    let mut counts = [0usize; 10];
    for (_, _, d) in &pop {
        counts[*d as usize] += 1;
    }
    let nf = n as f64;
    let mut digits = Vec::with_capacity(9);
    let mut mad = 0.0;
    for d in 1..=9u8 {
        let exp = (1.0 + 1.0 / d as f64).log10();
        let obs = counts[d as usize] as f64 / nf;
        mad += (obs - exp).abs();
        let num = (obs - exp).abs() - 1.0 / (2.0 * nf);
        let z = num.max(0.0) / (exp * (1.0 - exp) / nf).sqrt();
        digits.push(DigitRow {
            digit: d,
            count: counts[d as usize],
            observed: r4(obs),
            expected: r4(exp),
            z: (z * 100.0).round() / 100.0,
        });
    }
    mad /= 9.0;
    let conformity = if mad <= 0.006 {
        "close"
    } else if mad <= 0.012 {
        "acceptable"
    } else if mad <= 0.015 {
        "marginal"
    } else {
        "nonconformity"
    };
    let mut finding = None;
    if conformity == "nonconformity" {
        // Point the reviewer at the most over-represented significant digit.
        let worst = digits
            .iter()
            .filter(|r| r.observed > r.expected && r.z > 1.96)
            .max_by(|a, b| a.z.total_cmp(&b.z))
            .cloned();
        let p = must("P-015");
        let (msg, related) = match &worst {
            Some(w) => {
                let ids: Vec<i64> = pop.iter().filter(|x| x.2 == w.digit).map(|x| x.0).collect();
                (
                    format!(
                        "Leading digits depart from Benford's law (MAD {:.4}, nonconformity above 0.015). Digit {} appears {:.1}% of the time against {:.1}% expected (z {:.2}); its {} payments are listed for review.",
                        mad, w.digit, w.observed * 100.0, w.expected * 100.0, w.z, ids.len()
                    ),
                    ids,
                )
            }
            None => (format!("Leading digits depart from Benford's law (MAD {mad:.4}, nonconformity above 0.015)."), Vec::new()),
        };
        let mut f = Finding {
            rule_id: p.id,
            severity: Severity::Low,
            summary: msg.clone(),
            message: msg,
            evidence:
                json!({"mad": r4(mad), "tested": n, "worst_digit": worst.as_ref().map(|w| w.digit)})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            related: Vec::new(),
        };
        f.related = related;
        finding = Some(f);
    }
    Benford {
        tested: n,
        tested_from,
        mad: Some(r4(mad)),
        conformity,
        digits,
        skipped: None,
        finding,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jw_known_values() {
        assert!((jaro_winkler("martha", "marhta") - 0.9611).abs() < 1e-3);
        assert_eq!(jaro_winkler("acme", "acme"), 1.0);
        assert!(jaro_winkler("acme ltd", "acme limited") > 0.85);
        assert!(jaro_winkler("acme", "zeta") < 0.6);
    }

    #[test]
    fn invoice_numbers() {
        assert_eq!(numeric_suffix("INV-1043"), Some(("INV".into(), 1043)));
        assert_eq!(numeric_suffix("abc"), None);
        assert_eq!(invoice_key(" inv/0042 ").as_deref(), Some("INV0042"));
    }

    #[test]
    fn benford_conforming_population_passes() {
        // Geometric series is Benford-distributed.
        let mut items = Vec::new();
        let mut x = 10.0f64;
        for i in 0..2000 {
            items.push((i, Decimal::from_f64_retain(x).unwrap().round_dp(2)));
            x *= 1.0071;
            if x > 1e7 {
                x = 10.0;
            }
        }
        let b = benford(&items, &Config::default());
        assert!(
            matches!(b.conformity, "close" | "acceptable"),
            "{:?}",
            b.mad
        );
        assert!(b.finding.is_none());
    }

    #[test]
    fn benford_fabricated_population_flags() {
        let items: Vec<(i64, Decimal)> = (0..1000)
            .map(|i| (i, Decimal::new(500 + (i % 400) * 1000 + 13, 0)))
            .collect();
        let cfg = Config {
            benford_min_n: 100,
            ..Config::default()
        };
        // span 513..399513: more than two orders of magnitude
        let b = benford(&items, &cfg);
        assert_eq!(b.conformity, "nonconformity", "{:?} {:?}", b.mad, b.skipped);
        assert!(b.finding.is_some());
    }

    #[test]
    fn benford_respects_floor_and_size() {
        let items: Vec<(i64, Decimal)> = (0..50).map(|i| (i, Decimal::new(30000 + i, 0))).collect();
        let cfg = Config {
            benford_floor: Some(Decimal::new(25000, 0)),
            ..Config::default()
        };
        let b = benford(&items, &cfg);
        assert_eq!(b.conformity, "not_evaluated");
        assert_eq!(b.tested_from.as_deref(), Some("100000"));
    }
}
