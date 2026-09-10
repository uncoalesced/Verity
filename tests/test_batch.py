"""A folder of documents, and what happens when one of them is poison."""

from decimal import Decimal

from conftest import clean_reading, fake_toolbox

from verity.agent import batch
from verity.policy.rules import BLOCKED, PASS


def make_receipt(tmp_path, name):
    from PIL import Image

    path = tmp_path / name
    img = Image.new("RGB", (120, 120), "white")
    for x in range(10, 110):
        for y in range(40, 70):
            img.putpixel((x, y), (0, 0, 0))
    img.save(path)
    return path


def test_only_document_shaped_files_are_picked_up(tmp_path):
    make_receipt(tmp_path, "invoice.png")
    make_receipt(tmp_path, "receipt.jpg")
    (tmp_path / "notes.txt").write_text("not a document")
    (tmp_path / "subfolder").mkdir()

    found = [p.name for p in batch.iter_documents(tmp_path)]
    assert found == ["invoice.png", "receipt.jpg"]


def test_every_document_gets_audited_and_counted(tmp_path):
    for name in ("a.png", "b.png", "c.png"):
        make_receipt(tmp_path, name)

    report = batch.audit_directory(tmp_path, toolbox=fake_toolbox())
    assert report.documents == 3
    assert report.by_verdict[PASS] == 3
    assert report.errors == []


def test_one_bad_document_does_not_stop_the_batch(tmp_path):
    for name in ("a.png", "b.png", "c.png"):
        make_receipt(tmp_path, name)

    def explode_on_b(image, dayfirst=False):
        raise RuntimeError("model fell over")

    calls = {"n": 0}

    def read(image, dayfirst=False):
        calls["n"] += 1
        if calls["n"] == 2:
            return explode_on_b(image)
        return clean_reading()

    report = batch.audit_directory(tmp_path, toolbox=fake_toolbox(read_fields=read))
    assert report.documents == 2
    assert len(report.errors) == 1
    assert "model fell over" in report.errors[0][1]


def test_the_report_says_which_controls_did_the_holding(tmp_path):
    """A material amount with neither supplier nor date is unsubstantiated
    (P-001, high), so both documents are blocked rather than merely queried."""
    make_receipt(tmp_path, "a.png")
    make_receipt(tmp_path, "b.png")

    report = batch.audit_directory(
        tmp_path, toolbox=fake_toolbox(clean_reading(vendor=None, date=None))
    )
    assert report.by_verdict[BLOCKED] == 2
    assert report.by_rule["P-001"] == 2
    assert report.by_rule["P-003"] == 2
    assert report.by_rule["P-004"] == 2
    assert len(report.held) == 2


def test_limit_stops_early(tmp_path):
    for name in ("a.png", "b.png", "c.png"):
        make_receipt(tmp_path, name)

    report = batch.audit_directory(tmp_path, toolbox=fake_toolbox(), limit=2)
    assert report.documents == 2


def test_each_document_keeps_its_own_trace(tmp_path):
    make_receipt(tmp_path, "a.png")
    make_receipt(tmp_path, "b.png")

    report = batch.audit_directory(tmp_path, toolbox=fake_toolbox())
    run_ids = {r.trace.run_id for r in report.results}
    assert len(run_ids) == 2

# --- the two optional passes the batch script can run afterwards -----------
# Both sit after the controls have decided. Neither may change what they
# decided, and neither may report "nothing ran" as "all clear".


def _audit_folder():
    """Import the CLI script, which lives outside the package."""
    import importlib.util
    import sys
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "scripts" / "audit_folder.py"
    spec = importlib.util.spec_from_file_location("audit_folder", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["audit_folder"] = module
    spec.loader.exec_module(module)
    return module


def test_a_citation_pass_that_never_ran_is_not_reported_as_clean(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    make_receipt(tmp_path, "a.png")
    report = batch.audit_directory(
        tmp_path, toolbox=fake_toolbox(clean_reading(total=Decimal("18432.75")))
    )

    summary = _audit_folder()._check_citations(report)
    printed = capsys.readouterr().out

    assert "no citation check ran" in printed
    assert "supported its claim" not in printed
    assert summary["batch_usage"]["calls"] == 0


def test_the_citation_pass_leaves_the_verdicts_alone(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    make_receipt(tmp_path, "a.png")
    report = batch.audit_directory(
        tmp_path, toolbox=fake_toolbox(clean_reading(total=Decimal("18432.75")))
    )
    before = [(r.filename, r.verdict, [f.rule_id for f in r.findings]) for r in report.results]

    _audit_folder()._check_citations(report)

    after = [(r.filename, r.verdict, [f.rule_id for f in r.findings]) for r in report.results]
    assert after == before


def test_unconfigured_langfuse_says_so_and_sends_nothing(tmp_path, monkeypatch, capsys):
    from verity.obs import langfuse_export

    for name in langfuse_export.REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)
    make_receipt(tmp_path, "a.png")
    report = batch.audit_directory(tmp_path, toolbox=fake_toolbox())

    _audit_folder()._export_traces(report)

    assert "not configured" in capsys.readouterr().err
