# Engineered by uncoalesced
"""Generate Verity's brand assets from one grid. Deterministic: same seed, same art.

    uv run python scripts/make_assets.py

The mark is a ledger seen from far away: a bracket of documents, most of them
green (passed), a few amber (held for review), a few watermelon (blocked), with
the V of Verity picked out in pale green through the middle. Green for money
and profit, watermelon for loss.

Writes assets/verity-mark.svg, assets/verity-icon.svg, assets/verity-banner.svg,
assets/verity-social.svg and assets/verity-social.png (1200x630).
"""

from __future__ import annotations

import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets"

# Tokens (mirrored in DESIGN.md and crates/verity/src/report.rs).
INK = "#1F1F1D"
SURFACE = "#2B2B29"
TEXT = "#ECECE6"
MUTED = "#A3A39A"
PASS = "#7FA650"
PASS_DEEP = "#5E7A3E"
PASS_SOFT = "#9DBF6C"
V_PALE = "#C9D9B0"
REVIEW = "#F2994A"
BLOCKED = "#EF4F6B"

GRID = [
    "BBBBBBB...BBBBBBB",
    "BB.............BB",
    "BB.............BB",
    "BB.............BB",
    "BB.VV.......VV.BB",
    "BB..VV.....VV..BB",
    "BB...VV...VV...BB",
    "BB....VV.VV....BB",
    "BB.....VVV.....BB",
    "BB......V......BB",
    "BB.............BB",
    "BB.............BB",
    "BBBBBBB...BBBBBBB",
]
# A few documents are always blocked: the mark never shows a perfect ledger.
FORCED_BLOCKED = {(6, 0), (15, 8), (10, 12)}
PITCH = 30
CELL = 22


def cells(seed: int = 15):
    rng = random.Random(seed)
    out = []
    for r, row in enumerate(GRID):
        for c, ch in enumerate(row):
            if ch == ".":
                continue
            if ch == "V":
                out.append((c, r, rng.choice([V_PALE, V_PALE, PASS_SOFT]), "circle"))
                continue
            roll = rng.random()
            colour = (
                BLOCKED
                if roll < 0.04
                else REVIEW
                if roll < 0.11
                else rng.choice([PASS, PASS_DEEP, PASS_DEEP, PASS_SOFT])
            )
            shape = (
                "circle"
                if colour == REVIEW
                else "square"
                if colour == BLOCKED
                else rng.choice(["square", "circle"])
            )
            if (c, r) in FORCED_BLOCKED:
                colour, shape = BLOCKED, "square"
            out.append((c, r, colour, shape))
    return out


def svg_cells(ox: float, oy: float, scale: float = 1.0) -> str:
    parts = []
    p, s = PITCH * scale, CELL * scale
    for c, r, colour, shape in cells():
        x, y = ox + c * p, oy + r * p
        if shape == "circle":
            parts.append(
                f'<circle cx="{x + s / 2:.1f}" cy="{y + s / 2:.1f}" r="{s / 2:.1f}" fill="{colour}"/>'
            )
        else:
            parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{s:.1f}" height="{s:.1f}" rx="{3 * scale:.1f}" fill="{colour}"/>'
            )
    return "".join(parts)


W = len(GRID[0]) * PITCH - (PITCH - CELL)
H = len(GRID) * PITCH - (PITCH - CELL)
FONT = "ui-monospace, 'JetBrains Mono', 'SFMono-Regular', Menlo, Consolas, monospace"


def mark_svg() -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" role="img" aria-label="Verity">{svg_cells(0, 0)}</svg>\n'


def icon_svg() -> str:
    pad = 48
    size = max(W, H) + 2 * pad
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" role="img" aria-label="Verity">'
        f'<rect width="{size}" height="{size}" rx="56" fill="{INK}"/>{svg_cells((size - W) / 2, (size - H) / 2)}</svg>\n'
    )


def card_svg(w: int, h: int, tagline: str, facts: list[str]) -> str:
    scale = (h * 0.5) / H
    mx = h * 0.16
    my = (h - H * scale) / 2
    tx = mx + W * scale + h * 0.1
    fact_rows = "".join(
        f'<text x="{tx}" y="{h * 0.62 + i * h * 0.075:.0f}" font-family="{FONT}" font-size="{h * 0.034:.0f}" fill="{MUTED}">{f}</text>'
        for i, f in enumerate(facts)
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" role="img" aria-label="Verity">'
        f'<rect width="{w}" height="{h}" fill="{INK}"/>'
        f'<rect x="0" y="{h - 6}" width="{w * 0.70:.0f}" height="6" fill="{PASS}"/>'
        f'<rect x="{w * 0.70:.0f}" y="{h - 6}" width="{w * 0.18:.0f}" height="6" fill="{REVIEW}"/>'
        f'<rect x="{w * 0.88:.0f}" y="{h - 6}" width="{w * 0.12:.0f}" height="6" fill="{BLOCKED}"/>'
        f"{svg_cells(mx, my, scale)}"
        f'<text x="{tx}" y="{h * 0.36:.0f}" font-family="{FONT}" font-weight="700" font-size="{h * 0.13:.0f}" fill="{TEXT}">Verity</text>'
        f'<text x="{tx}" y="{h * 0.47:.0f}" font-family="{FONT}" font-size="{h * 0.04:.0f}" fill="{PASS_SOFT}">{tagline}</text>'
        f"{fact_rows}</svg>\n"
    )


def social_png(path: Path, tagline: str, facts: list[str]) -> None:
    from PIL import Image, ImageDraw, ImageFont

    w, h = 1200, 630
    img = Image.new("RGB", (w, h), INK)
    d = ImageDraw.Draw(img)

    def font(size: int, bold: bool = False):
        for name in (
            ["consolab.ttf", "DejaVuSansMono-Bold.ttf"] if bold else ["consola.ttf", "DejaVuSansMono.ttf"]
        ):
            try:
                return ImageFont.truetype(name, size)
            except OSError:
                continue
        return ImageFont.load_default()

    d.rectangle([0, h - 6, int(w * 0.70), h], fill=PASS)
    d.rectangle([int(w * 0.70), h - 6, int(w * 0.88), h], fill=REVIEW)
    d.rectangle([int(w * 0.88), h - 6, w, h], fill=BLOCKED)
    scale = (h * 0.5) / H
    mx, my = h * 0.16, (h - H * scale) / 2
    p, s = PITCH * scale, CELL * scale
    for c, r, colour, shape in cells():
        x, y = mx + c * p, my + r * p
        if shape == "circle":
            d.ellipse([x, y, x + s, y + s], fill=colour)
        else:
            d.rounded_rectangle([x, y, x + s, y + s], radius=3 * scale, fill=colour)
    tx = mx + W * scale + h * 0.1
    d.text((tx, h * 0.36), "Verity", font=font(int(h * 0.13), True), fill=TEXT, anchor="ls")
    d.text((tx, h * 0.47), tagline, font=font(int(h * 0.04)), fill=PASS_SOFT, anchor="ls")
    for i, f in enumerate(facts):
        d.text((tx, h * 0.62 + i * h * 0.075), f, font=font(int(h * 0.034)), fill=MUTED, anchor="ls")
    img.save(path, optimize=True)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    tagline = "Audits every invoice. Approves none."
    facts = [
        "18 written AP controls, zero guesswork",
        "1.7 MB binary · 28 ms MCP cold start",
        "90-95% fewer tokens than v1.0",
        "Every flag links back to its source",
    ]
    (OUT / "verity-mark.svg").write_text(mark_svg(), encoding="utf-8")
    (OUT / "verity-icon.svg").write_text(icon_svg(), encoding="utf-8")
    (OUT / "verity-social.svg").write_text(card_svg(1200, 630, tagline, facts), encoding="utf-8")
    (OUT / "verity-banner.svg").write_text(card_svg(1280, 400, tagline, facts[:2]), encoding="utf-8")
    social_png(OUT / "verity-social.png", tagline, facts)
    print("wrote", ", ".join(sorted(p.name for p in OUT.iterdir())))


if __name__ == "__main__":
    main()
