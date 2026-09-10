"""The surface an outside agent calls: POST /audit, the MCP tool, the schema.

Three things are being checked, and only these three. That the JSON endpoint
reaches the same verdict, through the same controls and the same ledger, as the
upload form does. That the MCP tool advertises a schema a client can actually
call and round-trips a real answer back. That the exported OpenAPI document is
valid against the specification.

None of this is evidence about any particular agent product. No Claude, Gemini,
Cursor, Codex or ChatGPT session is involved anywhere below -- the MCP client
here is the reference client from the SDK, connected in-process.
"""

import base64
import json

import anyio
import httpx
import pytest
from conftest import fake_toolbox
from fastapi.testclient import TestClient
from mcp import Client
from openapi_spec_validator import validate as validate_openapi

from verity import mcp_server
from verity.agent.tools import _no_history
from verity.api.main import app
from verity.policy.library import PolicyConfig

# An unsigned invoice over the signature threshold whose lines do not add up
# to its total: two controls with something to say about it.
UNSIGNED_FIELDS = {"total": "4820.75", "signature_present": False}

CLEAN_FIELDS = {
    "vendor": "Northwind Supplies",
    "date": "2026-06-20",
    "total": "1240.55",
    "line_items": [
        {"name": "Copier paper A4", "amount": "496.22"},
        {"name": "Toner cartridge", "amount": "744.33"},
    ],
    "signature_present": True,
    "confidence": 0.93,
}


@pytest.fixture
def client(session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr("verity.api.main.UPLOAD_DIR", tmp_path / "uploads")
    app.state.session_factory = session_factory
    # history left at the default, so the API is the thing responsible for
    # binding a ledger -- which is what the duplicate tests below check.
    app.state.toolbox = fake_toolbox(history=_no_history)
    app.state.config = PolicyConfig()
    with TestClient(app) as c:
        yield c


def audit(client, **body):
    return client.post("/audit", json=body)


# --- the endpoint ----------------------------------------------------------


def test_a_supplied_reading_is_audited_and_quotes_the_policy_it_failed(client):
    body = audit(client, filename="unsigned.pdf", fields={**CLEAN_FIELDS, **UNSIGNED_FIELDS}).json()

    assert body["verdict"] == "blocked"
    signature = next(f for f in body["findings"] if f["rule_id"] == "P-008")
    assert "signature" in signature["policy_text"].lower()
    # The reading the verdict was reached on comes back with it, confidence
    # included, so a caller can see what was judged and not just the answer.
    assert body["fields"]["total"] == "4820.75"
    assert body["fields"]["confidence"] == 0.93


def test_a_document_sent_as_base64_is_read_the_same_way_the_upload_form_reads_it(
    client, receipt_png
):
    with receipt_png.open("rb") as fh:
        uploaded = client.post("/documents", files={"file": ("invoice.png", fh, "image/png")}).json()

    encoded = base64.b64encode(receipt_png.read_bytes()).decode()
    posted = audit(client, filename="invoice.png", content_base64=encoded).json()

    # Same bytes, same reading. The second submission is a duplicate of the
    # first, which is P-002 doing its job rather than the two paths disagreeing.
    assert uploaded["verdict"] == "pass"
    assert posted["fields"] == uploaded["fields"]
    assert [f["rule_id"] for f in posted["findings"]] == ["P-002"]


def test_a_supplied_reading_is_compared_against_the_ledger_too(client):
    """P-002 and P-011 are dead on any entry point that forgets to bind history."""
    first = audit(client, filename="one.pdf", fields=CLEAN_FIELDS).json()
    second = audit(client, filename="two.pdf", fields=CLEAN_FIELDS).json()

    assert first["verdict"] == "pass"
    duplicate = next(f for f in second["findings"] if f["rule_id"] == "P-002")
    assert "Northwind" in duplicate["evidence"]["vendor"]


def test_the_trace_does_not_claim_a_page_was_read_that_never_was(client):
    body = audit(client, filename="fields-only.pdf", fields=CLEAN_FIELDS).json()

    steps = {step["tool"]: step for step in body["trace"]}
    assert "load_image" not in steps
    assert "supplied by the caller" in steps["read_fields"]["note"]
    assert steps["evaluate"]["result"]["verdict"] == "pass"


def test_sending_neither_payload_is_refused(client):
    assert audit(client, filename="nothing.pdf").status_code == 422


def test_sending_both_payloads_is_refused(client, receipt_png):
    encoded = base64.b64encode(receipt_png.read_bytes()).decode()
    res = audit(client, filename="both.pdf", content_base64=encoded, fields=CLEAN_FIELDS)
    assert res.status_code == 422


def test_a_body_that_is_not_base64_is_refused_rather_than_stored(client):
    res = audit(client, filename="junk.pdf", content_base64="not base64 at all!!")
    assert res.status_code == 422
    assert "base64" in res.json()["detail"]


def test_an_oversized_document_is_refused_before_it_is_decoded(client, monkeypatch):
    monkeypatch.setattr("verity.api.main.MAX_BASE64_CHARS", 16)
    res = audit(client, filename="huge.pdf", content_base64="A" * 64)
    assert res.status_code == 413


def test_an_unreadable_file_sent_as_base64_is_an_open_item(client):
    encoded = base64.b64encode(b"this is not a document").decode()
    body = audit(client, filename="junk.bin", content_base64=encoded).json()

    assert body["verdict"] == "blocked"
    assert [f["rule_id"] for f in body["findings"]] == ["P-014"]


# --- the MCP server --------------------------------------------------------


@pytest.fixture
def mcp_client(client, monkeypatch):
    """The SDK's own MCP client, talking to our server, talking to the app.

    The HTTP hop is real -- httpx serialises the request and FastAPI parses it
    -- it just arrives at the ASGI app in this process rather than over a
    socket. What that leaves untested is deployment: no uvicorn, no network,
    and no agent product at the other end.
    """
    monkeypatch.setattr(
        mcp_server,
        "_client",
        lambda: httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://verity"),
    )
    return Client(mcp_server.server)


def test_the_server_advertises_one_audit_tool_with_a_usable_schema(mcp_client):
    async def go():
        async with mcp_client as session:
            return await session.list_tools()

    tools = {tool.name: tool for tool in anyio.run(go).tools}
    assert "audit_document" in tools

    tool = tools["audit_document"]
    assert tool.input_schema["type"] == "object"
    assert set(tool.input_schema["properties"]) == {"filename", "content_base64", "fields"}
    # The description is the only thing telling an agent that the two payloads
    # are alternatives, and that a pass is not an instruction to pay.
    assert "exactly one" in tool.description
    assert "never approves" in tool.description


def test_calling_the_tool_returns_the_audit_the_api_produced(mcp_client):
    async def go():
        async with mcp_client as session:
            return await session.call_tool(
                "audit_document",
                {"filename": "unsigned.pdf", "fields": {**CLEAN_FIELDS, **UNSIGNED_FIELDS}},
            )

    result = anyio.run(go)
    assert not result.is_error
    body = json.loads(result.content[0].text)
    assert body["verdict"] == "blocked"
    assert "P-008" in [f["rule_id"] for f in body["findings"]]


def test_a_refused_request_reaches_the_agent_as_an_error_not_a_verdict(mcp_client):
    async def go():
        async with mcp_client as session:
            return await session.call_tool("audit_document", {"filename": "nothing.pdf"})

    result = anyio.run(go)
    assert result.is_error
    assert "422" in result.content[0].text


# --- the OpenAPI schema ----------------------------------------------------


def test_the_exported_schema_is_valid_openapi():
    from scripts.export_openapi import build

    schema = build("https://verity.example.com")
    validate_openapi(schema)  # raises if the document is not valid against the spec
    assert schema["servers"] == [{"url": "https://verity.example.com"}]


def test_the_schema_names_the_audit_operation_a_custom_gpt_would_call():
    from scripts.export_openapi import build

    operation = build("https://verity.example.com")["paths"]["/audit"]["post"]
    assert operation["operationId"] == "audit_document"
    assert operation["requestBody"]["content"]["application/json"]["schema"]
