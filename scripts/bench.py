# Engineered by uncoalesced
"""The Verity v1.1 benchmark. Offline, deterministic, one command.

    uv run python scripts/bench.py          # regenerate docs/BENCHMARK.md
    uv run python scripts/bench.py --check  # fail if the measured numbers moved

What it measures, on the hashed public snapshot in data/snapshot/ (see
scripts/fetch_public.py; nothing here touches the network):

1. Detection. Known anomalies are injected into copies of real payments
   (UK DCMS, USAspending) and real receipts (CORD). Each injected document is
   scored against its untouched original: it counts as *caught* only if it
   picks up a control its original did not. *Automatic* means a blocking
   (high-severity) control caught it with no human in the loop; *assisted*
   means any control raised it for review. Some injected types are ones no
   control is designed for -- they are in the headline on purpose.
2. False alarms. The share of untouched real documents a control flags.
3. Speed and size. Audit throughput, MCP cold start, response size.

The injector and the controls were written by the same people, so the designed
types are the easy part. The undesigned types and the false-alarm rate are the
honest part. Both are printed.
"""

from __future__ import annotations

import copy
import json
import random
import statistics
import subprocess
import sys
import tempfile
import time
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAP = ROOT / "data" / "snapshot"
BIN = ROOT / "target" / "release" / ("verity.exe" if sys.platform == "win32" else "verity")
OUT = ROOT / "docs" / "BENCHMARK.md"
SEED = 1729
PER_TYPE = 150
INJECT_BASE = 900_000_000_000

DESIGNED = {
    "exact_duplicate": "Same invoice resubmitted: same supplier, amount and date",
    "duplicate_shifted_date": "Resubmitted with the date moved 1-5 days",
    "duplicate_vendor_variant": "Resubmitted under a variant supplier name (typo, punctuation, Ltd/Limited) with the amount nudged up to 0.3%",
    "split_below_limit": "One purchase split into 2-3 invoices just under the approval limit inside a week",
    "future_dated": "Invoice dated after the audit date",
    "round_fabricated": "Invented invoice for a real supplier at a round amount",
    "altered_receipt_total": "Receipt total inflated 1-15% while subtotal and tax are left as printed",
}
UNDESIGNED = {
    "inflated_single_line": "Single-line payment inflated 3-12% (nothing printed to reconcile against)",
    "partial_rebill": "Same supplier billed again for 40-60% of an earlier amount",
    "ghost_vendor": "Payment to a supplier never seen before, plausible amount (no approved-supplier list configured)",
}


def run(args: list[str], stdin: str | None = None) -> str:
    p = subprocess.run(
        [str(BIN), *args], input=stdin, capture_output=True, text=True, encoding="utf-8", check=False
    )
    if p.returncode not in (0, 1):
        raise SystemExit(f"verity {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def audit(batch: dict, profile: str) -> tuple[dict, float]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump(batch, fh)
        tmp = fh.name
    try:
        out = json.loads(
            run(["audit", tmp, "--profile", str(ROOT / "profiles" / f"{profile}.json"), "--json"])
        )
    finally:
        Path(tmp).unlink(missing_ok=True)
    return out, out["timing_ms"]["audit"]


def load(name: str) -> dict:
    return json.loads((SNAP / f"{name}.json").read_text(encoding="utf-8"))


def d(x) -> Decimal:
    return Decimal(str(x))


def vendor_variant(rng: random.Random, v: str) -> str:
    choices = []
    if "Limited" in v:
        choices.append(v.replace("Limited", "Ltd"))
    if "Ltd" in v:
        choices.append(v.replace("Ltd", "Limited"))
    if len(v) > 6:
        i = rng.randrange(1, len(v) - 2)
        choices.append(v[:i] + v[i + 1] + v[i] + v[i + 2 :])  # transposition
        choices.append(v.replace(" ", "  ", 1).replace(",", "").replace(".", "") + ".")
    return rng.choice(choices) if choices else v + " Ltd"


def inject(docs: list[dict], kinds: list[str], rng: random.Random, today: str, limit: Decimal) -> list[dict]:
    """Return injected documents, each tagged with `_kind` and `_orig` (or None)."""
    out: list[dict] = []
    nid = INJECT_BASE
    pool = [x for x in docs if x.get("vendor") and x.get("date") and x.get("total")]
    vendors = sorted({x["vendor"] for x in pool})

    def new(base: dict | None, kind: str, **chg) -> dict:
        nonlocal nid
        nid += 1
        doc = copy.deepcopy(base) if base else {"currency": pool[0].get("currency")}
        doc.update(chg)
        doc["id"] = nid
        doc["source"] = {"file": f"seeded:{kind}", "row": nid - INJECT_BASE}
        doc["_kind"] = kind
        doc["_orig"] = base["id"] if base else None
        return doc

    def shift(date: str, days: int) -> str:
        import datetime as dt

        return (dt.date.fromisoformat(date) + dt.timedelta(days=days)).isoformat()

    for kind in kinds:
        for _ in range(PER_TYPE):
            b = rng.choice(pool)
            t = d(b["total"])
            if kind == "exact_duplicate":
                out.append(new(b, kind))
            elif kind == "duplicate_shifted_date":
                out.append(new(b, kind, date=shift(b["date"], rng.randint(1, 5))))
            elif kind == "duplicate_vendor_variant":
                bump = (t * d(rng.uniform(0, 0.003))).quantize(Decimal("0.01"))
                out.append(new(b, kind, vendor=vendor_variant(rng, b["vendor"]), total=str(t + bump)))
            elif kind == "split_below_limit":
                parts = rng.randint(2, 3)
                lo, hi = limit * d("0.905"), limit * d("0.995")
                for k in range(parts):
                    amt = (lo + (hi - lo) * d(rng.random())).quantize(Decimal("0.01"))
                    out.append(
                        new(
                            None,
                            kind,
                            vendor=b["vendor"],
                            date=shift(b["date"], k * rng.randint(0, 3)),
                            total=str(amt),
                            currency=b.get("currency"),
                        )
                    )
            elif kind == "future_dated":
                out.append(new(b, kind, date=shift(today, rng.randint(5, 60)), id=None))
            elif kind == "round_fabricated":
                amt = d(rng.choice([30, 35, 40, 45, 48, 50, 60, 75, 80, 90])) * 1000
                out.append(
                    new(
                        None,
                        kind,
                        vendor=rng.choice(vendors),
                        date=b["date"],
                        total=str(amt),
                        currency=b.get("currency"),
                    )
                )
            elif kind == "inflated_single_line":
                f = d(rng.uniform(1.03, 1.12))
                out.append(new(b, kind, total=str((t * f).quantize(Decimal("0.01"))), id=None))
                out[-1]["_replaces"] = b["id"]
            elif kind == "partial_rebill":
                f = d(rng.uniform(0.4, 0.6))
                out.append(
                    new(
                        b,
                        kind,
                        total=str((t * f).quantize(Decimal("0.01"))),
                        date=min(shift(b["date"], rng.randint(3, 40)), today),
                    )
                )
            elif kind == "ghost_vendor":
                name = (
                    rng.choice(["Apex", "Northgate", "Meridian", "Crescent", "Halcyon", "Brightwater"])
                    + " "
                    + rng.choice(["Consulting", "Services", "Solutions", "Advisory"])
                    + f" {rng.randint(10, 99)} Ltd"
                )
                out.append(
                    new(
                        None,
                        kind,
                        vendor=name,
                        date=b["date"],
                        total=str((t * d(rng.uniform(0.8, 1.2))).quantize(Decimal("0.01"))),
                        currency=b.get("currency"),
                    )
                )
    return out


def inject_receipts(docs: list[dict], rng: random.Random, clean_ids: set[int]) -> list[dict]:
    pool = [x for x in docs if x["id"] in clean_ids and x.get("subtotal") and x.get("tax")]
    out = []
    nid = INJECT_BASE
    for _ in range(PER_TYPE):
        b = rng.choice(pool)
        nid += 1
        x = copy.deepcopy(b)
        x["total"] = str((d(b["total"]) * d(rng.uniform(1.01, 1.15))).quantize(Decimal("1")))
        x["id"] = nid
        x["source"] = {"file": "seeded:altered_receipt_total", "row": nid - INJECT_BASE}
        x["_kind"], x["_orig"] = "altered_receipt_total", b["id"]
        out.append(x)
    return out


def score(result: dict, injected: list[dict], baseline: dict[int, set[str]]) -> dict[str, dict]:
    by_id = {r["id"]: r for r in result["documents"]}
    per: dict[str, dict] = {}
    for x in injected:
        r = by_id[x["id"]]
        before = baseline.get(x["_orig"] or x.get("_replaces") or -1, set())
        # New control, or a control that points straight back at the original.
        new = [
            f
            for f in r["findings"]
            if f["rule_id"] not in before or (x["_orig"] is not None and x["_orig"] in f.get("related", []))
        ]
        s = per.setdefault(x["_kind"], {"n": 0, "auto": 0, "assist": 0, "rules": {}})
        s["n"] += 1
        if any(f["severity"] == "high" for f in new):
            s["auto"] += 1
        if new:
            s["assist"] += 1
        for f in new:
            s["rules"][f["rule_id"]] = s["rules"].get(f["rule_id"], 0) + 1
    return per


def strip(doc: dict) -> dict:
    return {k: v for k, v in doc.items() if not k.startswith("_") and v is not None}


def merge(per: dict, part: dict) -> None:
    for k, v in part.items():
        acc = per.setdefault(k, {"n": 0, "auto": 0, "assist": 0, "rules": {}})
        for f in ("n", "auto", "assist"):
            acc[f] += v[f]
        for rk, rv in v["rules"].items():
            acc["rules"][rk] = acc["rules"].get(rk, 0) + rv


def detection() -> tuple[dict[str, dict], dict]:
    rng = random.Random(SEED)
    per: dict[str, dict] = {}
    fa: dict = {}
    kinds = list(DESIGNED)[:-1] + list(UNDESIGNED)
    for name, profile, today, limit in (
        ("uk_dcms", "uk_dcms", "2026-03-31", Decimal("25000.00")),
        ("usaspending", "usaspending", "2025-09-30", Decimal("10000.00")),
    ):
        data = load(name)
        clean, _ = audit({"documents": data["documents"]}, profile)
        baseline = {r["id"]: {f["rule_id"] for f in r["findings"]} for r in clean["documents"]}
        fa[name] = clean["summary"]
        fa[name]["p016_high"] = sum(
            any(f["rule_id"] == "P-016" and f["severity"] == "high" for f in r["findings"]) for r in clean["documents"]
        )
        ks =kinds if name == "uk_dcms" else [k for k in kinds if k != "split_below_limit"]
        # One run per anomaly type, each against the clean data, so injections
        # of one type can never mask or manufacture detections of another.
        for kind in ks:
            inj = inject(data["documents"], [kind], rng, today, limit)
            replaced = {x["_replaces"] for x in inj if "_replaces" in x}
            docs = [x for x in data["documents"] if x["id"] not in replaced] + [strip(x) for x in inj]
            res, _ = audit({"documents": docs}, profile)
            merge(per, score(res, inj, baseline))
    cord = load("cord")
    adjusted = set(cord.get("adjusted_receipts", []))
    clean, _ = audit({"documents": cord["documents"]}, "cord")
    baseline = {r["id"]: {f["rule_id"] for f in r["findings"]} for r in clean["documents"]}
    p7 = {r["id"] for r in clean["documents"] if "P-007" in baseline[r["id"]]}
    fa["cord"] = {
        "documents": len(cord["documents"]),
        "adjusted": len(adjusted),
        "p007_all": len(p7),
        "p007_unadjusted": len(p7 - adjusted),
        "unadjusted": len(cord["documents"]) - len(adjusted),
    }
    ok_ids = {r["id"] for r in clean["documents"]} - p7 - adjusted
    inj = inject_receipts(cord["documents"], rng, ok_ids)
    res, _ = audit({"documents": cord["documents"] + [strip(x) for x in inj]}, "cord")
    per.update(score(res, inj, baseline))
    return per, fa


def speed() -> dict:
    out = {}
    for name in ("uk_dcms", "usaspending", "cord"):
        times = []
        for _ in range(5):
            r, ms = audit(load(name), name)
            times.append(ms)
        n = r["summary"]["documents"]
        out[name] = {"documents": n, "audit_ms": statistics.median(times)}
    # MCP: spawn, initialize, one audit, exit -- what an agent pays per cold start.
    msgs = (
        "\n".join(
            json.dumps(m)
            for m in (
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "audit",
                        "arguments": {
                            "fields": json.loads(
                                (ROOT / "examples" / "arithmetic_discrepancy.json").read_text()
                            )
                        },
                    },
                },
            )
        )
        + "\n"
    )
    cold = []
    for _ in range(15):
        t0 = time.perf_counter()
        run(["mcp"], stdin=msgs)
        cold.append((time.perf_counter() - t0) * 1000)
    out["mcp_cold_ms"] = statistics.median(cold)
    out["binary_bytes"] = BIN.stat().st_size
    return out


def tokens() -> list[dict]:
    """Response size per golden fixture: v1.1 compact (default) and verbose,
    against the v1.0 finding payload (each finding with its policy title and
    full text, plus fields and thresholds -- what v1.0's audit returned before
    its trace, so this understates v1.0)."""
    sys.path.insert(0, str(ROOT / "src"))
    import datetime as dt

    from verity.cli import _parse_fields_from_dict
    from verity.policy.library import PolicyConfig
    from verity.policy.rules import AuditContext, evaluate, verdict

    rows = []
    for fx in sorted((ROOT / "examples").glob("*.json")):
        data = json.loads(fx.read_text(encoding="utf-8"))
        fields, hist = _parse_fields_from_dict(data)
        cfg = PolicyConfig()
        fs = evaluate(AuditContext(fields=fields, history=hist, config=cfg, today=dt.date(2026, 11, 1)))
        v10 = json.dumps(
            {
                "verdict": verdict(fs),
                "findings": [f.as_dict() for f in fs],
                "fields": fields.as_dict(),
                "thresholds": cfg.as_dict(),
            }
        )
        args = {"fields": {k: v for k, v in data.items() if k != "history"}, "today": "2026-11-01"}
        if "history" in data:
            args["history"] = data["history"]
        res = []
        for verbose in (False, True):
            a = dict(args, verbose=verbose)
            msgs = (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "audit", "arguments": a},
                    }
                )
                + "\n"
            )
            reply = json.loads(run(["mcp"], stdin=msgs).splitlines()[0])
            res.append(reply["result"]["content"][0]["text"])
        rows.append(
            {
                "fixture": fx.name,
                "v10": len(v10),
                "compact": len(res[0]),
                "verbose": len(res[1]),
                "compact_text": res[0],
            }
        )
    return rows


def fraud_eval_line() -> str:
    p = subprocess.run(
        [sys.executable, "-m", "verity.eval.fraud_eval"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=ROOT,
        check=False,
    )
    for line in p.stdout.splitlines():
        if line.startswith("caught "):
            return line.strip()
    return "fraud_eval did not run"


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f}%" if b else "n/a"


def render(per, fa, sp, tk, fe) -> tuple[str, str]:
    designed = [k for k in DESIGNED if k in per]
    undesigned = [k for k in UNDESIGNED if k in per]
    tot = {f: sum(per[k][f] for k in per) for f in ("n", "auto", "assist")}
    dz = {f: sum(per[k][f] for k in designed) for f in ("n", "auto", "assist")}
    uz = {f: sum(per[k][f] for k in undesigned) for f in ("n", "auto", "assist")}
    L = []
    L.append("<!-- deterministic:start -->")
    L.append("## Headline\n")
    L.append(
        f"On **{tot['n']:,} anomalies injected into real public payments and receipts**, Verity caught "
        f"**{pct(tot['auto'], tot['n'])} fully automatically** (a blocking control fired, no human involved) and "
        f"**{pct(tot['assist'], tot['n'])} with assistance** (raised for a reviewer).\n"
    )
    L.append(
        f"- Anomaly types the controls are built for: {pct(dz['auto'], dz['n'])} automatic, {pct(dz['assist'], dz['n'])} assisted ({dz['n']:,} cases).\n"
        f"- Types no control is built for, included on purpose: {pct(uz['auto'], uz['n'])} automatic, {pct(uz['assist'], uz['n'])} assisted ({uz['n']:,} cases).\n"
        f"- Independent labelled corpus (`fraud_eval`, labels written separately from the rules): {fe}.\n"
    )
    L.append("## By anomaly type\n")
    L.append("| Anomaly | Built for? | Cases | Automatic | Assisted | Controls that caught it |")
    L.append("|---|---|---:|---:|---:|---|")
    for k in designed + undesigned:
        s = per[k]
        rules = ", ".join(f"{r}×{c}" for r, c in sorted(s["rules"].items(), key=lambda x: -x[1])) or "none"
        desc = DESIGNED.get(k) or UNDESIGNED.get(k)
        L.append(
            f"| {desc} | {'yes' if k in DESIGNED else 'no'} | {s['n']} | {pct(s['auto'], s['n'])} | {pct(s['assist'], s['n'])} | {rules} |"
        )
    L.append(
        "\nA case counts as caught only if the injected document picks up a control its untouched original did not. Seed "
        f"{SEED}, {PER_TYPE} cases per type per dataset.\n"
    )
    L.append("## False alarms on untouched real data\n")
    L.append("| Dataset | Documents | Pass | Review | Blocked | Controls fired |")
    L.append("|---|---:|---:|---:|---:|---|")
    for name in ("uk_dcms", "usaspending"):
        s = fa[name]
        rules = ", ".join(f"{r}×{c}" for r, c in s["by_rule"].items())
        L.append(
            f"| {name} | {s['documents']:,} | {s['pass']:,} | {s['review']:,} | {s['blocked']:,} | {rules} |"
        )
    c = fa["cord"]
    L.append(
        f"\nCORD receipts (genuine, human-labelled): the arithmetic control P-007 fires on {c['p007_unadjusted']} of "
        f"{c['unadjusted']} receipts without discounts or extra charges ({pct(c['p007_unadjusted'], c['unadjusted'])}), "
        f"and on {c['p007_all']} of all {c['documents']} ({c['adjusted']} carry discounts the field schema cannot express).\n"
    )
    L.append(
        "What the flags on real data are: P-002 pairs are same-supplier, same-amount, same-day payments under different "
        "transaction numbers. They are held for a person to confirm, not declared fraud; the public files cannot say "
        "which are genuine. P-010 on government data is mostly round grant payments, which is why it is a review-level "
        "signal and never blocks. "
        f"P-016 blocks ({fa['uk_dcms']['p016_high']} UK, {fa['usaspending']['p016_high']} US) are the same supplier paid "
        "the identical amount again within a week under a different transaction number (for example, four payments of "
        "£36,695.29 to Historic England between 19 and 22 July 2024). Many will be agreed instalments; that is a "
        "question for a person with the contract, which is where Verity sends them.\n"
    )
    L.append("## Token cost per MCP response\n")
    L.append(
        "Bytes of response text (≈ tokens × 4). v1.0 figure is its finding payload without the trace, so it understates v1.0.\n"
    )
    L.append("| Fixture | v1.0 payload | v1.1 default | v1.1 verbose | Saving |")
    L.append("|---|---:|---:|---:|---:|")
    for r in tk:
        L.append(
            f"| {r['fixture']} | {r['v10']:,} | {r['compact']:,} | {r['verbose']:,} | {pct(r['v10'] - r['compact'], r['v10'])} |"
        )
    L.append("\nDefault response for `arithmetic_discrepancy.json`:\n")
    L.append(
        "```\n"
        + next(r["compact_text"] for r in tk if r["fixture"] == "arithmetic_discrepancy.json")
        + "\n```"
    )
    L.append("<!-- deterministic:end -->")
    det = "\n".join(L)
    T = [
        "## Speed (this machine, median)\n",
        "| Dataset | Documents | Audit time | Throughput |",
        "|---|---:|---:|---:|",
    ]
    for name in ("uk_dcms", "usaspending", "cord"):
        s = sp[name]
        rate = s["documents"] / (s["audit_ms"] / 1000) if s["audit_ms"] else 0
        T.append(f"| {name} | {s['documents']:,} | {s['audit_ms']:.1f} ms | {rate:,.0f} docs/s |")
    T.append(
        f"\nMCP cold start (spawn, initialize, one audit, exit): **{sp['mcp_cold_ms']:.0f} ms**. Binary: {sp['binary_bytes'] / 1e6:.1f} MB, no runtime dependencies.\n"
    )
    return det, "\n".join(T)


HEADER = """# Verity v1.1 benchmark

Generated by `uv run python scripts/bench.py` from the hashed snapshot in `data/snapshot/`
(verify with `verity verify data/snapshot/MANIFEST.json`). No network, no model, same numbers every run.

Data: UK Department for Culture, Media & Sport payments over £25,000, April 2024 - March 2026
(contains public sector information licensed under the Open Government Licence v3.0);
USAspending.gov contract transactions, National Science Foundation, FY2025 (public domain);
CORD v2 receipt labels (CC BY 4.0, Park et al. 2019).

"""


def main() -> int:
    check = "--check" in sys.argv
    if not BIN.exists():
        print("build first: cargo build --release")
        return 2
    print(run(["verify", str(SNAP / "MANIFEST.json")]).strip())
    per, fa = detection()
    tk = tokens()
    fe = fraud_eval_line()
    sp = speed() if not check else None
    det, timing = render(
        per,
        fa,
        sp
        or {n: {"documents": 0, "audit_ms": 0} for n in ("uk_dcms", "usaspending", "cord")}
        | {"mcp_cold_ms": 0, "binary_bytes": 1},
        tk,
        fe,
    )
    if check:
        old = OUT.read_text(encoding="utf-8")
        start, end = (
            old.index("<!-- deterministic:start -->"),
            old.index("<!-- deterministic:end -->") + len("<!-- deterministic:end -->"),
        )
        if old[start:end] == det:
            print("BENCH OK")
            return 0
        print("BENCH CHANGED: rerun scripts/bench.py and review the diff")
        return 1
    OUT.write_text(HEADER + det + "\n\n" + timing + "\n", encoding="utf-8")
    print(det.split("\n")[2])
    print(timing)
    return 0


if __name__ == "__main__":
    sys.exit(main())
