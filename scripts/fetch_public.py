# Engineered by uncoalesced
"""Fetch the public benchmark data once, into a hashed snapshot.

This is the only step in the benchmark that touches the network. Everything
after it (`verity verify`, `verity audit`, `scripts/bench.py`) reads the
snapshot and nothing else, and refuses to run if a hash has changed.

Sources, all official and licence-clear:

  uk_dcms      UK Department for Culture, Media & Sport, "transactions over
               £25,000", April 2024 - March 2026, from GOV.UK.
               Open Government Licence v3.0.
  usaspending  US federal contract transactions for one awarding agency,
               FY2025, from the official USAspending.gov API. Public domain.
  cord         CORD v2 receipt ground-truth labels (Clova AI), from the local
               Hugging Face cache populated by scripts/fetch_data.py. CC BY 4.0.

    uv run --with odfpy python scripts/fetch_public.py

Writes data/snapshot/raw/*, data/snapshot/<dataset>.json (normalised batches)
and data/snapshot/MANIFEST.json.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import time
import urllib.request
from decimal import Decimal, InvalidOperation
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAP = ROOT / "data" / "snapshot"
RAW = SNAP / "raw"
UA = "verity-benchmark/1.1 (+https://github.com/uncoalesced/Verity)"

GOVUK = "https://www.gov.uk/api/content/government/publications/"
UK_PUBLICATIONS = ["dcms-transactions-over-25000-2024-to-2025", "dcms-transactions-over-25000-2025-to-2026"]
USA_AGENCY = "National Science Foundation"
USA_FY = ("2024-10-01", "2025-09-30")
USA_PAGES = 40  # 100 transactions a page

LICENCES = {
    "uk_dcms": "Open Government Licence v3.0 - contains public sector information licensed under the OGL v3.0",
    "usaspending": "Public domain (U.S. Government work), USAspending.gov",
    "cord": "CC BY 4.0 - CORD: A Consolidated Receipt Dataset for Post-OCR Parsing (Park et al., 2019)",
}


def get(url: str, data: bytes | None = None) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL {url}")
    headers = {"User-Agent": UA}
    if data is not None:
        headers["Content-Type"] = "application/json"
    for attempt in range(4):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, data=data, headers=headers), timeout=90
            ) as r:
                return r.read()
        except Exception:
            if attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))
    raise RuntimeError("unreachable")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def money(v) -> Decimal | None:
    if v is None or v == "":
        return None
    try:
        return Decimal(str(v)).quantize(Decimal("0.01"))
    except InvalidOperation:
        return None


# --- UK -----------------------------------------------------------------------


def fetch_uk(files: list[dict]) -> list[dict]:
    import pandas as pd  # odfpy engine

    docs: dict[str, dict] = {}
    for slug in UK_PUBLICATIONS:
        meta = json.loads(get(GOVUK + slug))
        for att in meta["details"]["attachments"]:
            url = att.get("url", "")
            if not url.lower().endswith(".ods"):
                continue
            name = url.rsplit("/", 1)[-1]
            body = get(url)
            (RAW / name).write_bytes(body)
            digest = sha(body)
            files.append(
                {
                    "path": f"raw/{name}",
                    "sha256": digest,
                    "bytes": len(body),
                    "url": url,
                    "dataset": "uk_dcms",
                }
            )
            frame = pd.read_excel(RAW / name, engine="odf", header=None, dtype=str)
            header_row = next(
                i
                for i in range(min(10, len(frame)))
                if "supplier" in " ".join(map(str, frame.iloc[i])).lower()
            )
            cols = [str(c).strip().lower() for c in frame.iloc[header_row]]
            idx = {c: i for i, c in enumerate(cols)}

            def col(*names, idx=idx):
                for n in names:
                    if n in idx:
                        return idx[n]
                return None

            c_sup, c_amt, c_date = col("supplier"), col("amount"), col("date")
            c_txn, c_type = col("transaction number"), col("expense type")
            for r in range(header_row + 1, len(frame)):
                row = frame.iloc[r]
                amt = money(row.iloc[c_amt]) if c_amt is not None else None
                sup = row.iloc[c_sup] if c_sup is not None else None
                if amt is None or not isinstance(sup, str) or not sup.strip():
                    continue
                txn = str(row.iloc[c_txn]).strip().split(".")[0] if c_txn is not None else ""
                date = str(row.iloc[c_date])[:10] if c_date is not None else ""
                key = txn if txn.isdigit() else f"{name}:{r}"
                d = docs.setdefault(
                    key,
                    {
                        "id": int(txn) if txn.isdigit() else 10_000_000 + len(docs),
                        "vendor": sup.strip(),
                        "date": date,
                        "total": Decimal("0"),
                        "currency": "GBP",
                        "lines": [],
                        "source": {"file": f"raw/{name}", "row": r + 1, "sha256": digest, "url": url},
                    },
                )
                d["total"] += amt
                d["lines"].append(str(row.iloc[c_type]) if c_type is not None else "")
    out = []
    for d in docs.values():
        out.append(
            {
                "id": d["id"],
                "vendor": d["vendor"],
                "date": d["date"],
                "total": str(d["total"]),
                "currency": "GBP",
                "source": d["source"],
            }
        )
    out.sort(key=lambda x: (x["date"], x["id"]))
    return out


# --- USAspending ----------------------------------------------------------------


def fetch_usa(files: list[dict]) -> list[dict]:
    url = "https://api.usaspending.gov/api/v2/search/spending_by_transaction/"
    pages = []
    for page in range(1, USA_PAGES + 1):
        body = {
            "filters": {
                "time_period": [{"start_date": USA_FY[0], "end_date": USA_FY[1]}],
                "award_type_codes": ["A", "B", "C", "D"],
                "agencies": [{"type": "awarding", "tier": "toptier", "name": USA_AGENCY}],
            },
            "fields": [
                "Award ID",
                "Recipient Name",
                "Action Date",
                "Transaction Amount",
                "Award Type",
                "Mod",
            ],
            "limit": 100,
            "page": page,
            "sort": "Action Date",
            "order": "asc",
        }
        data = json.loads(get(url, json.dumps(body).encode()))
        pages.append({"request": body, "response": data})
        if not data.get("page_metadata", {}).get("hasNext"):
            break
    raw = json.dumps(pages, indent=1, sort_keys=True).encode()
    name = "usaspending_nsf_fy2025_contract_transactions.json"
    (RAW / name).write_bytes(raw)
    digest = sha(raw)
    files.append(
        {"path": f"raw/{name}", "sha256": digest, "bytes": len(raw), "url": url, "dataset": "usaspending"}
    )
    out = []
    n = 0
    for p in pages:
        for t in p["response"]["results"]:
            n += 1
            amt = money(t.get("Transaction Amount"))
            if amt is None or amt == 0:
                continue  # zero-dollar administrative modifications are not payments
            out.append(
                {
                    # Row in the raw file. USAspending's internal_id identifies the
                    # award, not the transaction, so it repeats; the award link is
                    # kept in source.url.
                    "id": n,
                    "vendor": t.get("Recipient Name"),
                    "date": t.get("Action Date"),
                    "total": str(amt),
                    "currency": "USD",
                    "source": {
                        "file": f"raw/{name}",
                        "row": n,
                        "sha256": digest,
                        "url": f"https://www.usaspending.gov/award/{t.get('generated_internal_id')}",
                    },
                }
            )
    return out


# --- CORD -------------------------------------------------------------------------


def fetch_cord(files: list[dict]) -> list[dict]:
    from datasets import load_dataset

    from verity.eval.datasets import DATASET_ID, cache_dir
    from verity.extraction.schema import parse_money

    lines = []
    for split in ("train", "validation", "test"):
        try:
            ds = load_dataset(DATASET_ID, split=split, cache_dir=str(cache_dir()))
        except Exception as exc:  # noqa: BLE001 -- any failure means the split is not cached locally
            print(f"cord {split}: skipped ({type(exc).__name__})")
            continue
        for i, gt in enumerate(ds["ground_truth"]):
            lines.append({"split": split, "index": i, "ground_truth": json.loads(gt)})
    raw = "\n".join(json.dumps(x, sort_keys=True, ensure_ascii=False) for x in lines).encode()
    name = "cord_v2_ground_truth.jsonl"
    (RAW / name).write_bytes(raw)
    digest = sha(raw)
    files.append(
        {
            "path": f"raw/{name}",
            "sha256": digest,
            "bytes": len(raw),
            "url": "https://huggingface.co/datasets/naver-clova-ix/cord-v2",
            "dataset": "cord",
        }
    )

    def pm(v):
        if isinstance(v, list):
            v = v[0] if v else None
        p = parse_money(v)
        return None if p is None else str(p)

    out = []
    for n, x in enumerate(lines, start=1):
        g = x["ground_truth"].get("gt_parse", {})
        tot = g.get("total") or {}
        sub = g.get("sub_total") or {}
        if isinstance(tot, list):
            tot = tot[0] if tot else {}
        if isinstance(sub, list):
            sub = sub[0] if sub else {}
        total = pm(tot.get("total_price"))
        if total is None:
            continue
        menu = g.get("menu") or []
        if isinstance(menu, dict):
            menu = [menu]
        items = []
        for m in menu:
            if not isinstance(m, dict):
                continue
            price = pm(m.get("price"))
            if price is None:
                continue
            items.append({"name": "item", "amount": price})
        extras = [pm(sub.get(k)) for k in ("tax_price", "service_price")]
        extras = [Decimal(e) for e in extras if e is not None]
        has_adjust = (
            any(k in sub for k in ("discount_price", "othersvc_price", "etc")) or "discount_price" in tot
        )
        doc = {
            "id": n,
            "total": total,
            "currency": "IDR",
            "line_items": items,
            "source": {
                "file": f"raw/{name}",
                "row": n,
                "sha256": digest,
                "url": f"cord-v2/{x['split']}/{x['index']}",
            },
        }
        if pm(sub.get("subtotal_price")) is not None:
            doc["subtotal"] = pm(sub.get("subtotal_price"))
        if extras:
            doc["tax"] = str(sum(extras))
        doc["_adjusted"] = has_adjust
        out.append(doc)
    return out


def main() -> int:
    RAW.mkdir(parents=True, exist_ok=True)
    files: list[dict] = []
    datasets = {}
    for name, fn in (("uk_dcms", fetch_uk), ("usaspending", fetch_usa), ("cord", fetch_cord)):
        print(f"fetching {name} ...", flush=True)
        docs = fn(files)
        meta = {k: d.pop("_adjusted") for k, d in ((d["id"], d) for d in docs) if "_adjusted" in d}
        batch = {"dataset": name, "licence": LICENCES[name], "documents": docs}
        if meta:
            batch["adjusted_receipts"] = sorted(k for k, v in meta.items() if v)
        body = json.dumps(batch, indent=0, ensure_ascii=False).encode()
        (SNAP / f"{name}.json").write_bytes(body)
        files.append(
            {
                "path": f"{name}.json",
                "sha256": sha(body),
                "bytes": len(body),
                "dataset": name,
                "derived": True,
            }
        )
        datasets[name] = {"documents": len(docs), "licence": LICENCES[name]}
        print(f"  {len(docs)} documents")
    manifest = {
        "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "datasets": datasets,
        "files": files,
    }
    (SNAP / "MANIFEST.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(f"wrote {len(files)} files to {SNAP}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
