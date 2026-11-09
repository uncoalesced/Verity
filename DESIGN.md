# Verity design language

## The mark

A ledger seen from a distance. A bracket of documents, each one a cell, with the
**V** of Verity picked out in pale green through the middle. Most cells are
green (they passed), a few are amber (held for a person), a few are watermelon
(blocked). The mark never shows a perfect ledger, because no real ledger is one.

Assets are generated, not drawn: `uv run python scripts/make_assets.py` writes
everything in `assets/` from one grid and one seed.

| File | Use |
|---|---|
| `assets/verity-mark.svg` | The mark alone, transparent background |
| `assets/verity-icon.svg` | App and avatar icon, dark rounded square |
| `assets/verity-banner.svg` | README hero, 1280×400 |
| `assets/verity-social.svg`, `.png` | Social card, 1200×630 |

## Colour

Green is money and profit. Watermelon is loss. Amber is the moment between them,
when a person has to look.

| Token | Hex | Meaning |
|---|---|---|
| `--pass` | `#7FA650` | Pass. No control objected |
| `--pass-deep` | `#5E7A3E` | Mark texture |
| `--pass-soft` | `#9DBF6C` | Mark texture, taglines |
| `--v-pale` | `#C9D9B0` | The V |
| `--review` | `#F2994A` | Review. A person decides |
| `--blocked` | `#EF4F6B` | Blocked. Payment held |
| `--ink` | `#1F1F1D` | Dark background |
| `--surface` | `#2B2B29` | Dark surface |
| `--text` | `#ECECE6` | Text on dark |
| `--muted` | `#A3A39A` | Secondary text |

## Shape carries meaning too

Colour is never the only signal, so the verdicts read the same in monochrome
and to colour-blind readers:

| Verdict | Shape | Terminal | Colour |
|---|---|---|---|
| Pass | square | `■ PASS` | `--pass` |
| Review | circle | `● REVIEW` | `--review` |
| Blocked | cross | `✕ BLOCKED` | `--blocked` |

The CLI honours `NO_COLOR` and `--no-color`. The HTML report follows the
reader's light or dark preference with the same tokens.

## Type

Monospace for the wordmark and for every number: `ui-monospace, JetBrains Mono,
SF Mono, Menlo, Consolas`. A figure in an audit should line up with the figure
above it. System sans for running text.

## Voice

Plain, specific, and never louder than the evidence. Verity says what it found,
quotes the policy, and stops. It never says "fraud". It says "held", "blocked",
"for review". It never claims a number it did not measure.
