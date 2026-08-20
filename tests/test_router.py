"""Ingestion quality triage. This is the trust boundary -- bad input must not reach extraction."""

import pytest
from PIL import Image
from pypdf import PdfWriter

from verity.ingestion.router import ACCEPTED, IMAGE, PDF, REJECTED, route, sniff_format

def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def inked_image():
    """An image with actual ink on it."""
    img = Image.new("RGB", (120, 120), "white")
    for x in range(10, 110):
        for y in range(40, 70):
            img.putpixel((x, y), (0, 0, 0))
    return img


def receipt_png(tmp_path, name="receipt.png"):
    path = tmp_path / name
    inked_image().save(path)
    return path


def receipt_pdf(tmp_path, name="invoice.pdf"):
    """One-page PDF carrying an image, the shape a scanned receipt actually arrives in."""
    path = tmp_path / name
    inked_image().save(path)
    return path


def blank_pdf(tmp_path, name="blank.pdf"):
    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    path = tmp_path / name
    with path.open("wb") as fh:
        writer.write(fh)
    return path


def test_sniff_format_uses_magic_bytes_not_extension():
    assert sniff_format(b"%PDF-1.7\n") == PDF
    assert sniff_format(b"\x89PNG\r\n\x1a\n") == IMAGE
    assert sniff_format(b"RIFF\x00\x00\x00\x00WEBP") == IMAGE
    assert sniff_format(b"hello world") is None


def test_accepts_real_image(tmp_path):
    result = route(receipt_png(tmp_path))
    assert result.status == ACCEPTED
    assert result.format == IMAGE
    assert result.ok


def test_accepts_pdf_with_content(tmp_path):
    result = route(receipt_pdf(tmp_path))
    assert result.status == ACCEPTED
    assert result.format == PDF


def test_rejects_blank_image(tmp_path):
    path = tmp_path / "blank.png"
    Image.new("RGB", (120, 120), "white").save(path)

    result = route(path)
    assert result.status == REJECTED
    assert "blank" in result.reason


def test_rejects_pdf_with_no_content(tmp_path):
    result = route(blank_pdf(tmp_path))
    assert result.status == REJECTED
    assert result.format == PDF


def test_rejects_empty_file(tmp_path):
    result = route(write(tmp_path, "empty.pdf", b""))
    assert result.status == REJECTED
    assert result.reason == "file is empty"


def test_rejects_truncated_image(tmp_path):
    good = receipt_png(tmp_path).read_bytes()
    result = route(write(tmp_path, "truncated.png", good[: len(good) // 2]))
    assert result.status == REJECTED
    assert "corrupt" in result.reason


def test_rejects_pdf_extension_on_non_pdf_bytes(tmp_path):
    """A .pdf name proves nothing; the bytes decide."""
    result = route(write(tmp_path, "notreally.pdf", b"just some text, honest"))
    assert result.status == REJECTED
    assert result.format is None
    assert "unsupported format" in result.reason


def test_rejects_oversized_file(tmp_path, monkeypatch):
    monkeypatch.setattr("verity.ingestion.router.MAX_BYTES", 10)
    result = route(receipt_pdf(tmp_path, "big.pdf"))
    assert result.status == REJECTED
    assert "exceeds" in result.reason


def test_rejects_missing_path(tmp_path):
    assert route(tmp_path / "nope.png").reason == "not a file"


def test_rejects_directory(tmp_path):
    assert route(tmp_path).reason == "not a file"


@pytest.mark.parametrize("payload", [b"%PDF-1.4\ngarbage", b"%PDF-1.4\n1 0 obj<</Type/Catalog>>"])
def test_malformed_pdf_is_rejected_not_raised(tmp_path, payload):
    result = route(write(tmp_path, "bad.pdf", payload))
    assert result.status == REJECTED
