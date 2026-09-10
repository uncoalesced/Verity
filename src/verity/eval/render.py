"""Turn a labelled row into a page a camera could have produced.

The fraud corpus is structured rows. The pipeline reads pictures. Something has
to bridge the two, and the honest bridge is to render an actual invoice and put
that through triage, extraction and the controls -- rather than building a
second, structured-input eval path that skips extraction and therefore proves
less about the system than the numbers would suggest.

What is deliberately *not* here: noise, skew, JPEG artefacts, varied templates,
handwriting. A rendered page is clean, crisply typeset and always the same
layout, which makes extraction's job easier than a scanned invoice would. Any
end-to-end number measured this way is therefore an upper bound on what the
reading step does with real post, and should be quoted as one.

ponytail: one fixed template, PIL's default bitmap font when no TrueType face is
available. Add templates and degradation when the question is "how robust is
extraction", not "does the pipeline run end to end".
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from verity.eval.fraud_cases import FraudCase

PAGE_SIZE = (1000, 1400)
MARGIN = 60
INK = (17, 17, 17)
PAPER = (252, 252, 250)
RULE = (170, 170, 170)

# Faces tried in order. All optional -- PIL's built-in bitmap font is the
# fallback, and the pipeline reads that too, just less prettily.
_FONT_CANDIDATES = ("DejaVuSans.ttf", "arial.ttf", "Helvetica.ttc")


def _font(size: int):
    for name in _FONT_CANDIDATES:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _money(value: Decimal | None, currency: str) -> str:
    return "" if value is None else f"{currency} {value:,.2f}".strip()


def render_fields(case: FraudCase) -> Image.Image:
    """Draw one invoice. Every number on the page comes off the case."""
    fields = case.fields
    currency = case.currency
    image = Image.new("RGB", PAGE_SIZE, PAPER)
    draw = ImageDraw.Draw(image)

    title = _font(44)
    heading = _font(26)
    body = _font(24)

    y = MARGIN
    draw.text((MARGIN, y), "INVOICE", font=title, fill=INK)
    y += 70
    draw.text((MARGIN, y), fields.vendor or "", font=heading, fill=INK)
    y += 40
    draw.text((MARGIN, y), f"Invoice no. {case.name}", font=body, fill=INK)
    y += 34
    draw.text((MARGIN, y), f"Date {fields.date.isoformat() if fields.date else ''}", font=body, fill=INK)

    y += 70
    draw.line([(MARGIN, y), (PAGE_SIZE[0] - MARGIN, y)], fill=RULE, width=2)
    y += 24

    # Rows, when the case has them. The CSV corpus carries none, so most pages
    # print a single summary line -- which is itself worth knowing, because it
    # is what the line-item reader will be handed.
    if fields.line_items:
        for item in fields.line_items:
            draw.text((MARGIN, y), item.name[:48], font=body, fill=INK)
            draw.text((640, y), _money(item.resolved_amount(), currency), font=body, fill=INK)
            y += 34
    else:
        draw.text((MARGIN, y), "Services rendered as per agreement", font=body, fill=INK)
        draw.text((640, y), _money(fields.subtotal, currency), font=body, fill=INK)
        y += 34

    y += 20
    draw.line([(MARGIN, y), (PAGE_SIZE[0] - MARGIN, y)], fill=RULE, width=2)
    y += 30

    for label, value in (
        ("Subtotal", fields.subtotal),
        ("Tax", fields.tax),
        ("Total", fields.total),
    ):
        if value is None:
            continue
        draw.text((420, y), label, font=body, fill=INK)
        draw.text((640, y), _money(value, currency), font=body, fill=INK)
        y += 36

    y += 40
    draw.text((MARGIN, y), "Payment due per agreed terms.", font=body, fill=INK)
    return image


def render_case(case: FraudCase, out_dir: str | Path) -> Path:
    """Render one case to `<out_dir>/<invoice id>.png` and return the path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{case.name}.png"
    render_fields(case).save(path)
    return path


def render_all(cases: list[FraudCase], out_dir: str | Path) -> list[Path]:
    return [render_case(case, out_dir) for case in cases]
