# Engineered by uncoalesced
"""Hold the Rust engine to the Python one.

Every case the Python evals know about -- the 19 policy_eval cases, every row
of every sample fraud corpus with its full ledger, the golden fixtures, and any
normalised real-data batch passed on the command line -- is evaluated by both
engines. The 14 shared controls (P-001..P-014) must agree exactly: same
controls, same severities, same messages, same evidence. Anything the Rust
engine adds (P-015+) is counted and reported, never compared.

    uv run python scripts/parity.py [data/snapshot/*.json ...]

Prints PARITY OK and exits 0 only on zero differences.
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
import tempfile
from decimal import Decimal
from pathlib import Path

from verity.eval import cases as policy_cases
from verity.eval import fraud_cases
from verity.eval.policy_eval import TODAY
from verity.extraction.schema import ExtractedFields, LineItem
from verity.policy.library import PolicyConfig
from verity.policy.rules import AuditContext, PriorDocument, evaluate, normalize_vendor, verdict

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target" / "release" / ("verity.exe" if sys.platform == "win32" else "verity")
LEGACY = {f"P-{i:03d}" for i in range(1, 15)}


def _s(v: Decimal | None) -> str | None:
    return None if v is None else str(v)


def fields_json(f: ExtractedFields) -> dict:
    return {
        "vendor": f.vendor,
        "date": f.date.isoformat() if f.date else None,
        "total": _s(f.total),
        "subtotal": _s(f.subtotal),
        "tax": _s(f.tax),
        "line_items": [
            {
                "name": i.name,
                "quantity": _s(i.quantity),
                "unit_price": _s(i.unit_price),
                "amount": _s(i.amount),
            }
            for i in f.line_items
        ],
        "signature_present": f.signature_present,
        "confidence": f.confidence,
    }


def config_json(c: PolicyConfig) -> dict:
    d = c.as_dict()
    d["approved_vendors"] = sorted(c.approved_vendors)
    return d


def history_json(h: list[PriorDocument]) -> list[dict]:
    return [
        {
            "document_id": p.document_id,
            "vendor": p.vendor,
            "total": _s(p.total),
            "date": p.date.isoformat() if p.date else None,
        }
        for p in h
    ]


def request(ctx: AuditContext) -> dict:
    return {
        "fields": fields_json(ctx.fields),
        "history": history_json(ctx.history),
        "config": config_json(ctx.config),
        "today": ctx.today.isoformat(),
        "document_id": ctx.document_id,
        "filename": ctx.filename or "document",
        "ingestion_status": ctx.ingestion_status,
        "reject_reason": ctx.reject_reason,
    }


def contexts() -> list[tuple[str, AuditContext]]:
    out: list[tuple[str, AuditContext]] = []
    for c in policy_cases.CASES:
        out.append(
            (
                f"policy_eval:{c.name}",
                AuditContext(
                    fields=c.fields,
                    config=c.config,
                    filename=c.name,
                    ingestion_status=c.ingestion_status,
                    reject_reason=c.reject_reason,
                    history=c.history,
                    today=TODAY,
                ),
            )
        )
    for csv_path in sorted(fraud_cases.CORPUS_DIR.glob("*.csv")):
        for c in fraud_cases.build_cases(path=csv_path):
            out.append(
                (
                    f"{csv_path.name}:{c.name}",
                    AuditContext(
                        fields=c.fields,
                        config=c.config,
                        document_id=c.document_id,
                        history=c.history,
                        today=c.today,
                    ),
                )
            )
    for fx in sorted((ROOT / "examples").glob("*.json")):
        data = json.loads(fx.read_text(encoding="utf-8"))
        hist = [
            PriorDocument(
                document_id=int(h["document_id"]),
                vendor=h.get("vendor"),
                total=Decimal(str(h["total"])) if h.get("total") is not None else None,
                date=dt.date.fromisoformat(h["date"]) if h.get("date") else None,
            )
            for h in data.get("history", [])
        ]
        items = [
            LineItem(
                name=i.get("name", "Item"),
                quantity=Decimal(str(i["quantity"])) if i.get("quantity") is not None else None,
                unit_price=Decimal(str(i["unit_price"])) if i.get("unit_price") is not None else None,
                amount=Decimal(str(i["amount"])) if i.get("amount") is not None else None,
            )
            for i in data.get("line_items", [])
        ]
        f = ExtractedFields(
            vendor=data.get("vendor"),
            date=dt.date.fromisoformat(data["date"]) if data.get("date") else None,
            total=Decimal(str(data["total"])) if data.get("total") is not None else None,
            subtotal=Decimal(str(data["subtotal"])) if data.get("subtotal") is not None else None,
            tax=Decimal(str(data["tax"])) if data.get("tax") is not None else None,
            line_items=items,
            signature_present=data.get("signature_present"),
            confidence=float(data.get("confidence", 1.0)),
        )
        out.append(
            (
                f"examples:{fx.name}",
                AuditContext(fields=f, history=hist, today=dt.date(2026, 11, 1), filename=fx.name),
            )
        )
    return out


def batch_contexts(path: Path) -> list[tuple[str, AuditContext]]:
    """A normalised real-data batch ({"documents": [...], "config": {...}}), each
    document audited against same-supplier documents in the lookback window --
    the same neighbourhood `verity audit` builds."""
    data = json.loads(path.read_text(encoding="utf-8"))
    cfg_raw = data.get("config") or {}
    config = PolicyConfig(
        approval_limit=Decimal(str(cfg_raw.get("approval_limit", "10000.00"))),
        stale_after_days=int(cfg_raw.get("stale_after_days", 90)),
    )
    docs = data["documents"]
    priors = []
    for d in docs:
        priors.append(
            PriorDocument(
                document_id=int(d["id"]),
                vendor=d.get("vendor"),
                total=Decimal(str(d["total"])) if d.get("total") not in (None, "") else None,
                date=dt.date.fromisoformat(d["date"]) if d.get("date") else None,
            )
        )
    by_vendor: dict[str, list[PriorDocument]] = {}
    for p in priors:
        if p.vendor and p.date:
            by_vendor.setdefault(normalize_vendor(p.vendor), []).append(p)
    out = []
    default_today = dt.date.fromisoformat(data["today"]) if data.get("today") else dt.date.today()
    for d, me in zip(docs, priors):
        today = dt.date.fromisoformat(d["today"]) if d.get("today") else default_today
        anchor = dt.date.fromisoformat(d["today"]) if d.get("today") else (me.date or today)
        cutoff = anchor - dt.timedelta(days=180)
        hist = [
            p
            for p in by_vendor.get(normalize_vendor(me.vendor), [])
            if p.document_id != me.document_id and p.date >= cutoff
        ]
        items = [
            LineItem(name=i.get("name", "Item"), amount=Decimal(str(i["amount"])) if i.get("amount") is not None else None)
            for i in d.get("line_items", [])
        ]
        f = ExtractedFields(
            vendor=me.vendor,
            date=me.date,
            total=me.total,
            subtotal=Decimal(str(d["subtotal"])) if d.get("subtotal") not in (None, "") else None,
            tax=Decimal(str(d["tax"])) if d.get("tax") not in (None, "") else None,
            line_items=items,
            confidence=1.0,
        )
        out.append(
            (
                f"{path.name}:{d['id']}",
                AuditContext(fields=f, config=config, document_id=me.document_id, history=hist, today=today),
            )
        )
    return out


def batch_path(path: Path) -> tuple[int, int]:
    """Compare the path the benchmark actually uses: `verity audit <batch>` with
    default thresholds, document by document, against the Python engine on the
    same neighbourhood. Returns (documents, differences). P-010's v1.1
    `currency` evidence key is dropped before comparing: Python has no currency."""
    proc = subprocess.run([str(BIN), "audit", str(path), "--json"], capture_output=True, text=True, encoding="utf-8", check=False)
    rust = {d["id"]: d for d in json.loads(proc.stdout)["documents"]}
    diffs = 0
    for name, ctx in batch_contexts(path):
        r = [
            {**f, "evidence": {k: v for k, v in f["evidence"].items() if k != "currency"}}
            for f in rust[ctx.document_id]["findings"]
            if f["rule_id"] in LEGACY
        ]
        r = [{"rule_id": f["rule_id"], "severity": f["severity"], "message": f["message"], "evidence": f["evidence"]} for f in r]
        p = py_result(ctx)
        if r != p["findings"]:
            diffs += 1
            if diffs <= 5:
                print(f"BATCH DIFF {name}")
                print(f"  python: {p['findings']}")
                print(f"  rust:   {r}")
    return len(rust), diffs


def py_result(ctx: AuditContext) -> dict:
    fs = evaluate(ctx)
    return {
        "verdict": verdict(fs),
        "findings": [
            json.loads(
                json.dumps(
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "message": f.message,
                        "evidence": f.evidence,
                    }
                )
            )
            for f in fs
        ],
    }


def legacy_verdict(findings: list[dict]) -> str:
    sev = {f["severity"] for f in findings}
    return "blocked" if "high" in sev else "review" if sev & {"medium", "low"} else "pass"


def main() -> int:
    if not BIN.exists():
        print(f"build first: cargo build --release ({BIN} missing)")
        return 2
    cases = contexts()
    for arg in sys.argv[1:]:
        cases += batch_contexts(Path(arg))
    reqs = [request(ctx) for _, ctx in cases]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump(reqs, fh)
        tmp = fh.name
    try:
        proc = subprocess.run(
            [str(BIN), "_parity", tmp], capture_output=True, text=True, encoding="utf-8", check=False
        )
    finally:
        Path(tmp).unlink(missing_ok=True)
    if proc.returncode != 0:
        print(proc.stderr)
        return 2
    rust = json.loads(proc.stdout)
    diffs = 0
    extra: dict[str, int] = {}
    for (name, ctx), r in zip(cases, rust):
        p = py_result(ctx)
        r_legacy = [f for f in r["findings"] if f["rule_id"] in LEGACY]
        for f in r["findings"]:
            if f["rule_id"] not in LEGACY:
                extra[f["rule_id"]] = extra.get(f["rule_id"], 0) + 1
        if r_legacy != p["findings"] or legacy_verdict(r_legacy) != p["verdict"]:
            diffs += 1
            if diffs <= 10:
                print(f"DIFF {name}\n  python: {p}\n  rust:   {r_legacy}")
    print(f"{len(cases)} cases compared on P-001..P-014 (single-document path); {diffs} differences")
    for arg in sys.argv[1:]:
        currencies = {d.get("currency") for d in json.loads(Path(arg).read_text(encoding="utf-8"))["documents"]}
        if currencies - {None, "GBP", "USD", "EUR"}:
            # v1.1 thresholds for these currencies differ from v1.0 by design.
            print(f"{Path(arg).name}: batch path not compared ({', '.join(sorted(c for c in currencies if c))} use v1.1 currency rules)")
            continue
        n, bd = batch_path(Path(arg))
        print(f"{Path(arg).name}: {n} documents compared through the batch path; {bd} differences")
        diffs += bd
    if extra:
        print(
            "v1.1 controls also fired (not compared): "
            + ", ".join(f"{k}x{v}" for k, v in sorted(extra.items()))
        )
    if diffs == 0:
        print("PARITY OK")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
