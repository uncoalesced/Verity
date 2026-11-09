# Changelog

## v1.1.0 (2026-11-09)

Verity v1.1 moves the verdict engine to Rust and ships it as one native binary
(CLI, offline HTML reports and an MCP server), adds four forensic controls, and
publishes a benchmark measured on real public data.

### Measured (docs/BENCHMARK.md, reproducible offline)

- 70.4% of injected anomalies of the types the controls are built for are blocked with no human involved, and 99.7% are raised for review. Across every injected type, including three no control is built to catch, the figures are 48.8% and 69.1% (2,931 cases on real UK government payments, US federal contracts and labelled receipts).
- About 150,000 payments a second. MCP cold start (spawn, initialize, audit, exit) is 28 ms. The binary is 1.7 MB.
- An MCP audit response is 79 to 164 bytes, 90 to 95% smaller than v1.0's.
- The Rust and Python engines agree with 0 differences: 17,647 documents audited one at a time (every real row included) and 3,528 real payments audited as batches.

### Added

- `verity-core`, the Rust policy engine. Pure functions with no I/O, no clock and `#![forbid(unsafe_code)]`. All fourteen v1.0 controls are ported message-for-message.
- The `verity` binary:
  - `audit` (JSON or CSV, single document or batch) with `--report` (offline HTML with drill-down provenance) and `--csv` (formula-safe export).
  - `explain`.
  - `verify` (offline snapshot hash check).
  - `mcp` over stdio, or `--http` (private and token-gated).
- MCP tools `audit`, `audit_batch`, `explain` and `trace`. Output is compact by default; `verbose` returns full evidence and `record` writes to the Postgres ledger.
- New controls:
  - P-015 Benford first-digit conformity: population-level, and aware of truncated lists such as spend over £25k.
  - P-016 near-duplicate payment: fuzzy supplier name, amount within 0.5%, within 7 days. The same supplier and the same amount is blocked.
  - P-017 reused invoice number.
  - P-018 sequential invoice numbering.
- Currency awareness: P-010 round-amount thresholds and P-007 rounding tolerance are set per currency.
- Provenance: every document carries its source file, row and sha256, and every cross-document finding carries the ids it relates to.
- Cross-document controls report `not_evaluated` when no history is available, instead of passing silently.
- Alembic migration 0004 adds `invoice_number`, `currency` and `source_sha256` to extractions, plus a vendor and date index.
- Public benchmark data, hashed and committed: UK DCMS payments over £25k (OGL v3.0), USAspending NSF FY2025 contracts (public domain) and CORD v2 labels (CC BY 4.0).
- Scripts: `fetch_public.py`, `bench.py`, `parity.py`, `smoke.py` and `make_assets.py`.
- Design language: the bracket-V dot-matrix mark, green, amber and watermelon tokens, and shape-coded verdicts (`DESIGN.md`, `assets/`).
- Distribution:
  - Release workflow: binaries for Linux (x64 and arm64), macOS (Intel and Apple Silicon) and Windows, plus a GHCR image.
  - `server.json` for the official MCP registry and `Dockerfile`.
  - Smithery config updated to the binary.
  - Install blocks for Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Gemini CLI, Antigravity, Codex and ChatGPT (Action).

### Security

- Strict input: unknown fields are rejected, strings and lists are capped, and amounts must be plain decimals.
- Document text never appears in default MCP output. Verbose output labels it as data.
- No MCP tool touches files, processes or the network.
- HTTP mode: localhost by default, constant-time bearer token, Origin allowlist and body cap.
- HTML report escaped under a strict CSP. CSV guarded against formula injection.

### Changed

- The Python console script is now `verity-py`, so `verity` always means the native binary. `verity-mcp` (the v1.0 HTTP-client server) is unchanged.
- Version 1.1.0 across the Python package, API, CLI, Cargo workspace, Smithery and registry metadata.
- In batch mode the history lookback is anchored to each document's own date, so a historical file is audited the way it would have been at the time.
