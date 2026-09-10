"""Audit a folder of documents and write the exception report.

The batch entry point for a period close: point it at a folder of scanned
invoices and receipts, get back a verdict for every one of them plus a CSV of
everything that needs a person.

    uv run scripts/audit_folder.py ./inbox --out exceptions.csv

Nothing is written to the database unless --save is passed, so this is safe to
run against a folder just to see what it would say.

Two optional passes run after the controls have decided and cannot change what
they decided:

--check-citations   asks Claude whether the policy quoted on each finding
                    actually supports it, and prints what the batch cost
--trace-to-langfuse ships a copy of each trace to Langfuse; Verity keeps its
                    own trace either way
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from verity.agent import batch
from verity.policy.library import PolicyConfig


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit every document in a folder")
    ap.add_argument("directory", help="folder of invoices and receipts")
    ap.add_argument("--recursive", action="store_true", help="include subfolders")
    ap.add_argument("--limit", type=int, default=None, help="stop after this many documents")
    ap.add_argument("--out", default="exceptions.csv", help="where to write the exception report")
    ap.add_argument("--json", dest="json_out", default=None, help="also write the full result as JSON")
    ap.add_argument(
        "--save",
        action="store_true",
        help="persist every run to the database (needs DATABASE_URL and migrations applied)",
    )
    ap.add_argument(
        "--check-citations",
        action="store_true",
        help="ask Claude whether each finding's quoted policy supports it (needs ANTHROPIC_API_KEY)",
    )
    ap.add_argument(
        "--trace-to-langfuse",
        action="store_true",
        help="also send each trace to Langfuse (needs the obs extra and LANGFUSE_* keys)",
    )
    args = ap.parse_args()

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"not a folder: {directory}", file=sys.stderr)
        return 2

    config = PolicyConfig()
    saved: list = []
    toolbox = None
    on_result = None

    if args.save:
        from verity.agent.history import db_history
        from verity.agent.tools import default_toolbox, with_history
        from verity.db import persist
        from verity.db.session import SessionLocal
        from verity.ingestion.router import route

        session = SessionLocal()
        # Bind the ledger so duplicate payment and threshold splitting have
        # something to compare against, then write each document as it is
        # audited so later documents in the same batch can see earlier ones.
        toolbox = with_history(default_toolbox(), db_history(session))

        def on_result(result, path):
            document = persist.record_document(session, path, route(path))
            persist.record_extraction(session, document.id, result)
            run = persist.save_audit(session, result, config=config, document_id=document.id)
            session.commit()
            saved.append(run)
    else:
        print(
            "note: running without --save, so no ledger is available. The "
            "duplicate-payment (P-002) and threshold-splitting (P-011) controls "
            "cannot fire on this run.",
            file=sys.stderr,
        )

    report = batch.audit_directory(
        directory,
        toolbox=toolbox,
        config=config,
        recursive=args.recursive,
        limit=args.limit,
        on_result=on_result,
    )
    batch.print_report(report)

    # The CSV comes off the stored rows when they exist and off the in-memory
    # results otherwise, through the same column set either way, so the report
    # is available whether or not a database is configured.
    from verity.reporting import exceptions as reporting

    csv_text = reporting.to_csv(saved) if (args.save and saved) else reporting.results_to_csv(report.results)
    Path(args.out).write_text(csv_text, encoding="utf-8")
    held = len(report.held)
    print(f"\nwrote {args.out} ({held} item(s) needing a person)")

    citations = _check_citations(report) if args.check_citations else None
    if args.trace_to_langfuse:
        _export_traces(report)

    if args.json_out:
        payload = report.as_dict()
        if citations is not None:
            payload["citations"] = citations
        Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"wrote {args.json_out}")

    return 1 if report.errors else 0


def _check_citations(report) -> dict:
    """Second-opinion pass over every finding, with the batch bill at the end.

    Deliberately after the audit, over the results it already produced: this
    cannot reach back and change a verdict, and a document that was held stays
    held whatever comes back.
    """
    from verity.llm.citation_check import check_findings
    from verity.obs.cost import total

    per_document, usages, unsupported = {}, [], []
    for result in report.results:
        checks = check_findings(result.findings)
        usages.append(checks.usage)
        per_document[result.filename] = checks.as_dict()
        unsupported += [(result.filename, c.rule_id, c.reason) for c in checks.unsupported]

    spend = total(usages)
    ran = sum(d["ran"] for d in per_document.values())
    print(f"\nchecked {ran} citation(s) across {len(per_document)} document(s)")
    if unsupported:
        print("policy citations that may not support their finding:")
        for filename, rule_id, reason in unsupported:
            print(f"  {filename}: {rule_id} -- {reason}")
    elif ran:
        print("every finding's quoted policy supported its claim")
    else:
        # Nothing ran. Never report that as a clean bill of health.
        print("no citation check ran (set ANTHROPIC_API_KEY to enable it)")

    if spend.calls:
        floor = "" if spend.priced else " (a floor -- some calls had no published price)"
        print(f"cost ${spend.cost_usd} over {spend.calls} call(s), {spend.total_tokens} tokens{floor}")

    return {"per_document": per_document, "batch_usage": spend.as_dict()}


def _export_traces(report) -> None:
    from verity.obs.langfuse_export import enabled, export_trace

    if not enabled():
        print(
            "note: --trace-to-langfuse was passed but Langfuse is not configured "
            "(needs the obs extra and LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY). "
            "Nothing was sent; the trace on each result is unaffected.",
            file=sys.stderr,
        )
        return
    sent = sum(
        int(export_trace(r.trace, verdict=r.verdict, filename=r.filename)) for r in report.results
    )
    print(f"sent {sent}/{len(report.results)} trace(s) to Langfuse")


if __name__ == "__main__":
    raise SystemExit(main())
