"""Write the OpenAPI schema a Custom GPT Action imports.

ChatGPT's consumer product integrates through function-calling Actions rather
than MCP, so it needs a schema rather than a server. This writes one out of the
running app's own routes, which means it cannot describe an endpoint that does
not exist or drift from one that changed:

    uv run scripts/export_openapi.py --out openapi.json

`--server` is the only thing the app cannot know: an Action calls a URL that is
reachable from ChatGPT, not the localhost the app is bound to. Pass the public
base URL, or set VERITY_PUBLIC_URL.

The audit endpoint is `audit_document`, and it is the one an Action needs. The
rest of the queue and reporting routes are exported alongside it because they
are the same API and cost nothing to include; a Custom GPT can be pointed at
the whole file or an edited-down copy of it.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from verity.api.main import app


def build(server_url: str) -> dict:
    """The app's schema, with the one field a served app cannot infer filled in."""
    schema = app.openapi()
    schema["servers"] = [{"url": server_url.rstrip("/")}]
    return schema


def main() -> int:
    ap = argparse.ArgumentParser(description="Export the OpenAPI schema for ChatGPT Actions")
    ap.add_argument("--out", default="openapi.json", help="where to write the schema")
    ap.add_argument(
        "--server",
        default=os.getenv("VERITY_PUBLIC_URL", "http://127.0.0.1:8000"),
        help="base URL an Action will call (default: $VERITY_PUBLIC_URL)",
    )
    args = ap.parse_args()

    schema = build(args.server)
    out = Path(args.out)
    out.write_text(json.dumps(schema, indent=2), encoding="utf-8")

    print(f"wrote {out} ({schema['openapi']}, {len(schema['paths'])} paths) for {args.server}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
