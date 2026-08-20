"""Ingestion trust boundary.

Files arrive from users, so nothing here assumes well-formed input: every check
runs against the bytes on disk, not the filename or the caller's claim about it.
A file leaves this module either ACCEPTED with a known format, or REJECTED with
a reason -- extraction is never handed anything that failed to decode.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageStat, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PyPdfError

log = logging.getLogger(__name__)

ACCEPTED = "accepted"
REJECTED = "rejected"

PDF = "pdf"
IMAGE = "image"

MAX_BYTES = 25 * 1024 * 1024
# Pixel ceiling guards against decompression bombs; PIL's own default is laxer.
MAX_PIXELS = 50_000_000
Image.MAX_IMAGE_PIXELS = MAX_PIXELS

# Below this grayscale standard deviation the page carries no ink worth reading.
BLANK_STDDEV = 3.0

# Leading bytes -> format. Checked against file content, never the extension.
MAGIC = (
    (b"%PDF-", PDF),
    (b"\x89PNG\r\n\x1a\n", IMAGE),
    (b"\xff\xd8\xff", IMAGE),  # JPEG
    (b"GIF87a", IMAGE),
    (b"GIF89a", IMAGE),
    (b"BM", IMAGE),
    (b"II*\x00", IMAGE),  # TIFF little-endian
    (b"MM\x00*", IMAGE),  # TIFF big-endian
)


@dataclass(frozen=True)
class TriageResult:
    path: Path
    status: str
    format: str | None = None
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == ACCEPTED


def _reject(path: Path, reason: str, fmt: str | None = None) -> TriageResult:
    log.info("rejected %s: %s", path, reason)
    return TriageResult(path=path, status=REJECTED, format=fmt, reason=reason)


def sniff_format(head: bytes) -> str | None:
    """Format from magic bytes. RIFF/WEBP needs the container tag, so it is separate."""
    for magic, fmt in MAGIC:
        if head.startswith(magic):
            return fmt
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return IMAGE
    return None


def _triage_pdf(path: Path) -> TriageResult:
    try:
        reader = PdfReader(path)
        if reader.is_encrypted and reader.decrypt("") == 0:
            return _reject(path, "pdf is password protected", PDF)
        pages = reader.pages
        if len(pages) == 0:
            return _reject(path, "pdf has no pages", PDF)
        for page in pages:
            if (page.extract_text() or "").strip() or len(page.images) > 0:
                return TriageResult(path=path, status=ACCEPTED, format=PDF)
    except (PyPdfError, ValueError, OSError, KeyError, RecursionError) as exc:
        # pypdf raises a wide spread of errors on malformed xref tables and streams.
        return _reject(path, f"unreadable pdf: {type(exc).__name__}", PDF)
    return _reject(path, "pdf has no text or images on any page", PDF)


def _triage_image(path: Path) -> TriageResult:
    try:
        with Image.open(path) as probe:
            probe.verify()  # catches truncated/corrupt streams, consumes the file object
        with Image.open(path) as img:
            gray = img.convert("L")
            stddev = ImageStat.Stat(gray).stddev[0]
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError) as exc:
        return _reject(path, f"corrupt image: {type(exc).__name__}", IMAGE)
    except Image.DecompressionBombError:
        return _reject(path, "image exceeds pixel limit", IMAGE)
    if stddev < BLANK_STDDEV:
        return _reject(path, f"image is blank (stddev {stddev:.2f})", IMAGE)
    return TriageResult(path=path, status=ACCEPTED, format=IMAGE)


def route(path: str | Path) -> TriageResult:
    """Detect format and reject anything extraction cannot use.

    Returns a TriageResult; never raises for bad input, only for a bad call.
    """
    path = Path(path)

    if not path.is_file():
        return _reject(path, "not a file")

    try:
        size = path.stat().st_size
    except OSError as exc:
        return _reject(path, f"unreadable file: {type(exc).__name__}")

    if size == 0:
        return _reject(path, "file is empty")
    if size > MAX_BYTES:
        return _reject(path, f"file exceeds {MAX_BYTES} bytes")

    try:
        with path.open("rb") as fh:
            head = fh.read(16)
    except OSError as exc:
        return _reject(path, f"unreadable file: {type(exc).__name__}")

    fmt = sniff_format(head)
    if fmt == PDF:
        return _triage_pdf(path)
    if fmt == IMAGE:
        return _triage_image(path)
    return _reject(path, "unsupported format (not pdf or image)")
