"""Verity as a tool an outside agent can call.

This is a client of the HTTP API, not a second copy of it. The tool below posts
to `POST /audit` and hands back what comes out; every control, threshold and
citation stays on the server side, so an agent calling over MCP gets the same
verdict, recorded in the same table, as the review screen does. Nothing here
decides anything.

MCP is the integration path because four of the five agents this is aimed at --
Claude, Gemini CLI, Cursor and Codex -- speak it natively. ChatGPT's consumer
product does not, and is served by the OpenAPI schema `scripts/export_openapi.py`
writes out of the same endpoint.

Run it over stdio, which is what every MCP client above expects:

    uv run verity-mcp

The API has to be up and reachable at `VERITY_API_URL` (default
http://127.0.0.1:8000). The server does not start one.
"""

from __future__ import annotations

import os

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

API_URL = os.getenv("VERITY_API_URL", "http://127.0.0.1:8000").rstrip("/")
# An audit that has to read a page runs an extraction model, which on a cold
# checkpoint is slow. Long enough that a real read is not cut off, finite so a
# dead API surfaces as an error rather than a hang.
TIMEOUT = float(os.getenv("VERITY_MCP_TIMEOUT", "300"))

server = MCPServer("verity")


def _client() -> httpx.AsyncClient:
    """The HTTP client the tool calls through. Substituted in tests."""
    return httpx.AsyncClient(base_url=API_URL, timeout=TIMEOUT)


@server.tool()
async def audit_document(
    filename: str = "document",
    content_base64: str | None = None,
    fields: dict | None = None,
) -> dict:
    """Audit one invoice or receipt against a written set of accounts-payable controls.

    Send exactly one of `content_base64` or `fields`.

    `content_base64` is the document file itself (PDF or image), base64-encoded;
    Verity reads it. `fields` is a reading you already did, as
    {"vendor", "date" (YYYY-MM-DD), "total", "subtotal", "tax", "line_items":
    [{"name", "quantity", "unit_price", "amount"}], "signature_present",
    "confidence"}; no model runs and the controls are applied to your numbers.
    Leave out anything you could not read rather than sending a zero -- an
    unread total and a total of nothing lead to opposite verdicts.

    Returns the verdict ("pass", "review" or "blocked"), every finding with the
    full text of the policy it fired under, the fields the verdict was reached on,
    the thresholds in force, and the step-by-step trace.

    Verity never approves or releases a payment. A "pass" means no control
    objected, not that the invoice should be paid.
    """
    payload: dict = {"filename": filename}
    if content_base64 is not None:
        payload["content_base64"] = content_base64
    if fields is not None:
        payload["fields"] = fields

    try:
        async with _client() as client:
            response = await client.post("/audit", json=payload)
    except httpx.RequestError as exc:
        # The API is not up, or not where this server was told to look. Named
        # explicitly: an agent told only that the tool failed cannot tell an
        # unreachable server from an invoice it got wrong.
        raise ToolError(f"could not reach the verity api at {API_URL}: {exc}") from exc

    if response.is_error:
        # A refusal is an error, never a result: an agent that read one as a
        # verdict would report an invoice as audited when nothing audited it.
        # `ToolError` rather than a bare raise, because that is the one the SDK
        # passes through with its message intact -- anything else reaches the
        # agent as "Error executing tool audit_document" and nothing more.
        raise ToolError(f"verity api returned {response.status_code}: {response.text[:500]}")
    return response.json()


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
