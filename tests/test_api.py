"""The HTTP surface, against SQLite and a fake reader.

No Postgres, no checkpoint download. What is being checked here is the wiring
and the contract, not the models -- those are covered where they live.
"""

import csv
import io

import pytest
from conftest import clean_reading, fake_toolbox
from fastapi.testclient import TestClient

from verity.api.main import app
from verity.policy.library import PolicyConfig


@pytest.fixture
def client(session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr("verity.api.main.UPLOAD_DIR", tmp_path / "uploads")
    app.state.session_factory = session_factory
    app.state.toolbox = fake_toolbox()
    app.state.config = PolicyConfig()
    with TestClient(app) as c:
        yield c


def upload(client, receipt_png, name="invoice.png"):
    with receipt_png.open("rb") as fh:
        return client.post("/documents", files={"file": (name, fh, "image/png")})


def test_health_reports_the_size_of_the_control_library(client):
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["controls"] == 14


def test_uploading_a_document_returns_a_verdict_with_its_reasons(client, receipt_png):
    res = upload(client, receipt_png)
    assert res.status_code == 201
    body = res.json()
    assert body["verdict"] == "pass"
    assert body["fields"]["vendor"] == "Northwind Supplies"
    assert body["trace"]


def test_a_held_document_names_the_control_and_quotes_the_policy(client, receipt_png):
    app.state.toolbox = fake_toolbox(clean_reading(vendor=None))
    body = upload(client, receipt_png).json()

    assert body["verdict"] == "review"
    finding = next(f for f in body["findings"] if f["rule_id"] == "P-003")
    assert "supplier" in finding["policy_text"].lower()


def test_the_queue_lists_runs_with_a_summary(client, receipt_png):
    upload(client, receipt_png)
    app.state.toolbox = fake_toolbox(clean_reading(total=None))
    upload(client, receipt_png, "second.png")

    body = client.get("/runs").json()
    assert len(body["runs"]) == 2
    assert body["summary"]["by_verdict"]["blocked"] == 1
    assert body["summary"]["by_verdict"]["pass"] == 1


def test_one_run_can_be_fetched_by_id(client, receipt_png):
    run_id = upload(client, receipt_png).json()["run_id"]
    body = client.get(f"/runs/{run_id}").json()
    assert body["run_id"] == run_id


def test_an_unknown_run_is_a_404_not_an_empty_result(client):
    assert client.get("/runs/does-not-exist").status_code == 404


def test_a_reviewer_decision_is_recorded_against_a_name(client, receipt_png):
    run_id = upload(client, receipt_png).json()["run_id"]
    res = client.post(
        f"/runs/{run_id}/review",
        json={"decision": "approved", "reviewer": "A. Controller", "rationale": "Checked."},
    )
    assert res.status_code == 201
    assert res.json()["review"]["reviewer"] == "A. Controller"


def test_clearing_a_blocked_document_is_recorded_as_an_override(client, receipt_png):
    app.state.toolbox = fake_toolbox(clean_reading(total=None))
    run_id = upload(client, receipt_png).json()["run_id"]

    body = client.post(
        f"/runs/{run_id}/review",
        json={"decision": "approved", "reviewer": "A. Controller"},
    ).json()
    assert body["review"]["overrides_verdict"] is True


def test_an_unknown_decision_is_rejected(client, receipt_png):
    run_id = upload(client, receipt_png).json()["run_id"]
    res = client.post(
        f"/runs/{run_id}/review", json={"decision": "shipped", "reviewer": "A. Controller"}
    )
    assert res.status_code == 422


def test_the_exception_report_downloads_as_csv(client, receipt_png):
    app.state.toolbox = fake_toolbox(clean_reading(vendor=None))
    upload(client, receipt_png)

    res = client.get("/reports/exceptions.csv")
    assert res.status_code == 200
    rows = list(csv.DictReader(io.StringIO(res.text)))
    assert rows[0]["filename"].endswith("invoice.png")
    assert "P-003" in rows[0]["rule_ids"]


def test_the_control_library_is_readable_over_http(client):
    controls = client.get("/policies").json()["controls"]
    assert len(controls) == 14
    assert all(c["text"] for c in controls)


def test_policies_can_be_searched_in_plain_language(client):
    hits = client.get("/policies/search", params={"q": "invoice paid twice"}).json()["hits"]
    assert hits[0]["policy_id"] == "P-002"


def test_a_rejected_file_is_an_open_item_not_a_clean_pass(client, tmp_path):
    from PIL import Image

    blank = tmp_path / "blank.png"
    Image.new("RGB", (60, 60), "white").save(blank)

    with blank.open("rb") as fh:
        body = client.post("/documents", files={"file": ("blank.png", fh, "image/png")}).json()

    assert body["verdict"] == "blocked"
    assert [f["rule_id"] for f in body["findings"]] == ["P-014"]


def test_the_audit_pack_is_available_for_the_file(client, receipt_png):
    run_id = upload(client, receipt_png).json()["run_id"]
    pack = client.get(f"/runs/{run_id}/pack").json()
    assert pack["thresholds_in_force"]["approval_limit"]
    assert pack["review_history"] == []


def test_the_review_queue_page_is_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "Verity" in res.text


def test_the_same_invoice_submitted_twice_is_caught_as_a_duplicate(client, receipt_png):
    """The end-to-end proof that the ledger is actually wired in.

    P-002 and P-011 compare a document against what is already on file. If
    nothing binds the ledger lookup they cannot fire at all, and the queue looks
    clean while duplicates go through.
    """
    from PIL import Image

    from verity.agent.tools import Toolbox, _no_history

    reading = clean_reading()
    # history is left at the default, so the API is the thing responsible for
    # binding a ledger. That is exactly what this test is checking.
    app.state.toolbox = Toolbox(
        load_image=lambda path: Image.new("RGB", (64, 64), "white"),
        read_fields=lambda image, dayfirst=False: reading,
        read_field=lambda image, field_name, question=None: "",
        detect_signature=lambda image: (True, 0.91),
        history=_no_history,
    )

    first = upload(client, receipt_png, "invoice.png").json()
    assert first["verdict"] == "pass"

    second = upload(client, receipt_png, "invoice-again.png").json()
    assert second["verdict"] == "blocked"
    duplicate = next(f for f in second["findings"] if f["rule_id"] == "P-002")
    assert "Northwind" in duplicate["evidence"]["vendor"]


def test_an_injected_history_is_not_overridden_by_the_api(client, receipt_png):
    """A caller that supplied its own ledger keeps it."""
    app.state.toolbox = fake_toolbox()  # history=lambda fields: []
    upload(client, receipt_png, "one.png")
    body = upload(client, receipt_png, "two.png").json()
    assert [f["rule_id"] for f in body["findings"]] == []
