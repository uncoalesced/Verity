# Engineered by uncoalesced
"""Command-line interface for Verity.

Enables instant, deterministic auditing of extracted invoice JSON fixtures
and documents directly from the terminal without database dependencies.
Also provides subcommands for launching the MCP server and checking version.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from decimal import Decimal
from pathlib import Path

from verity.extraction.schema import ExtractedFields, LineItem
from verity.policy.library import PolicyConfig
from verity.policy.rules import AuditContext, PriorDocument, evaluate, verdict, worst_severity

__version__ = "1.1.0"


def _parse_fields_from_dict(data: dict) -> tuple[ExtractedFields, list[PriorDocument]]:
    """Parse fields and optional ledger history from a dictionary."""
    fields_dict = data.get("fields", data)

    items = []
    for item in fields_dict.get("line_items", []):
        qty = Decimal(str(item["quantity"])) if item.get("quantity") is not None else None
        unit = Decimal(str(item["unit_price"])) if item.get("unit_price") is not None else None
        amt = Decimal(str(item["amount"])) if item.get("amount") is not None else None
        items.append(LineItem(name=item.get("name", "Item"), quantity=qty, unit_price=unit, amount=amt))

    total = Decimal(str(fields_dict["total"])) if fields_dict.get("total") is not None else None
    subtotal = Decimal(str(fields_dict["subtotal"])) if fields_dict.get("subtotal") is not None else None
    tax = Decimal(str(fields_dict["tax"])) if fields_dict.get("tax") is not None else None

    date_val = fields_dict.get("date")
    parsed_date = None
    if date_val:
        if isinstance(date_val, dt.date):
            parsed_date = date_val
        else:
            parsed_date = dt.date.fromisoformat(str(date_val))

    fields = ExtractedFields(
        vendor=fields_dict.get("vendor"),
        date=parsed_date,
        total=total,
        subtotal=subtotal,
        tax=tax,
        line_items=items,
        signature_present=fields_dict.get("signature_present"),
        confidence=float(fields_dict.get("confidence", 1.0)),
        raw=fields_dict,
    )

    history_list = []
    for h in data.get("history", []):
        h_total = Decimal(str(h["total"])) if h.get("total") is not None else None
        h_date = dt.date.fromisoformat(str(h["date"])) if h.get("date") is not None else None
        history_list.append(
            PriorDocument(
                document_id=int(h.get("document_id", 1)),
                vendor=h.get("vendor"),
                total=h_total,
                date=h_date,
            )
        )

    return fields, history_list


def audit_fixture(path: Path | str, today: dt.date | None = None) -> int:
    """Audit a JSON fixture or document and print formatted report."""
    target_path = Path(path)
    if not target_path.exists():
        print(f"Error: file not found: {target_path}", file=sys.stderr)
        return 2

    with target_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    fields, history = _parse_fields_from_dict(data)

    ctx = AuditContext(
        fields=fields,
        config=PolicyConfig(),
        history=history,
        today=today or dt.date.today(),
        filename=target_path.name,
    )

    findings = evaluate(ctx)
    v = verdict(findings)
    worst = worst_severity(findings)

    print("=" * 70)
    print("VERITY DETERMINISTIC AUDIT REPORT")
    print("=" * 70)
    print(f"Target:    {target_path}")
    print(f"Vendor:    {fields.vendor or '<missing>'}")
    print(f"Date:      {fields.date.isoformat() if fields.date else '<missing>'}")
    print(f"Total:     {fields.total if fields.total is not None else '<unsubstantiated>'}")
    print(f"Verdict:   {v.upper()}")
    print(f"Severity:  {worst.upper() if worst else 'NONE'}")
    print(f"Findings:  {len(findings)} policy violation(s)")
    print("-" * 70)

    if not findings:
        print("Status: All 14 statutory AP controls satisfied. No exceptions.")
    else:
        for idx, f in enumerate(findings, 1):
            print(f"[{f.severity.upper()}] {f.rule_id}: {f.policy_title}")
            print(f"Reason: {f.message}")
            if f.policy_text:
                print(f'Policy: "{f.policy_text.strip()}"')
            if idx < len(findings):
                print("-" * 40)
    print("=" * 70)

    return 0 if v == "pass" else 1


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="verity",
        description="Verity: Deterministic Pre-Payment Accounts Payable Auditor & Policy Engine (Engineered by uncoalesced)",
    )
    parser.add_argument("--version", "-v", action="version", version=f"Verity v{__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    audit_parser = subparsers.add_parser("audit", help="Deterministically audit a JSON fixture or document")
    audit_parser.add_argument("file", help="Path to invoice JSON fixture or file to audit")
    audit_parser.add_argument("--today", help="Reference audit date (YYYY-MM-DD)", default=None)

    subparsers.add_parser("mcp", help="Run the Verity MCP server over stdio")

    args = parser.parse_args(argv)

    if args.command == "audit":
        audit_date = None
        if args.today:
            audit_date = dt.date.fromisoformat(args.today)
        exit_code = audit_fixture(args.file, today=audit_date)
        sys.exit(exit_code)
    elif args.command == "mcp":
        from verity.mcp_server import main as mcp_main

        mcp_main()
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
