"""Toolbox: the callable surface the agent loop is built against. Each tool is
swappable -- that is what makes the loop testable at all -- so what matters
here is that the *default* wiring behaves: real image loading for both input
shapes the pipeline accepts, and the placeholder tools that ship as sane,
inert defaults."""

from __future__ import annotations

from decimal import Decimal

import pytest
from PIL import Image
from pypdf import PdfWriter

from verity.agent.tools import (
    PageLoadError,
    Toolbox,
    default_toolbox,
    history_from_documents,
    load_page_image,
)
from verity.extraction.schema import ExtractedFields
from verity.policy.rules import PriorDocument


def inked_image() -> Image.Image:
    """An image with actual ink on it, the same fixture ingestion's tests use."""
    img = Image.new("RGB", (120, 120), "white")
    for x in range(10, 110):
        for y in range(40, 70):
            img.putpixel((x, y), (0, 0, 0))
    return img


def test_load_page_image_from_a_real_image(tmp_path):
    path = tmp_path / "receipt.png"
    inked_image().save(path)

    image = load_page_image(path)
    assert image.mode == "RGB"
    assert image.size == (120, 120)


def test_load_page_image_from_a_pdf_with_an_embedded_image(tmp_path):
    path = tmp_path / "invoice.pdf"
    inked_image().save(path)  # Pillow's PDF writer embeds the source image as a page image

    image = load_page_image(path)
    assert image.mode == "RGB"
    assert image.size[0] > 0
    assert image.size[1] > 0


def test_load_page_image_raises_on_a_pdf_with_no_embedded_image(tmp_path):
    path = tmp_path / "blank.pdf"
    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    with path.open("wb") as fh:
        writer.write(fh)

    with pytest.raises(PageLoadError, match="no embedded page image"):
        load_page_image(path)


def test_default_toolbox_builds_with_real_callables():
    toolbox = default_toolbox()
    assert isinstance(toolbox, Toolbox)
    assert toolbox.signature_detection_enabled is True
    # No ledger configured by default -- the cross-document rules see nothing.
    assert toolbox.history(ExtractedFields()) == []


def test_default_toolbox_accepts_overrides():
    sentinel = object()
    toolbox = default_toolbox(triage=lambda path: sentinel)
    assert toolbox.triage("whatever") is sentinel
    # Everything not overridden keeps the real default.
    assert toolbox.signature_detection_enabled is True


def test_history_from_documents_returns_a_fixed_ledger():
    rows = [PriorDocument(document_id=1, vendor="Acme", total=Decimal("10"))]
    lookup = history_from_documents(rows)

    assert lookup(ExtractedFields()) == rows
    # A defensive copy each call -- the caller cannot mutate the fixture through it.
    assert lookup(ExtractedFields()) is not rows
