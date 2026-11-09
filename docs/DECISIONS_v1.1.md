# Verity v1.1 — plan

## Context
v1.0 (commit `f28be38`) works but is heavy: the MCP server (`src/verity/mcp_server.py`) is an HTTP client to FastAPI, which needs Postgres and pulls torch/transformers. Every audit returns full policy text and trace, which is token-expensive. There is no real public spend data and no forensic depth beyond 14 controls. Goal: ship v1.1 tonight as a public, postable release. It should be fast, token-lean, forensically strong, provenance-linked, secure against prompt injection, with a coherent visual identity, measured honestly on real public data, and installable in every major agent.

## Decisions (settled in grilling, 2026-11-09)
| # | Decision |
|---|---|
| Q1 | Start writing Rust alongside Python. Rust core = controls, schema, verdicts, CLI, native MCP. Python keeps extraction (ML), FastAPI, agent loop, evals. No full rewrite. Python "optimize" half follows `python_refactor.md` (untracked, stays out of commits unless told). |
| Q2 | Two implementations tonight + parity test (all fixtures, eval cases, AND every real benchmark row). PyO3 swap later. |
| Q3/Q13 | Keep the dot-matrix bracket-V. Palette green (pass/profit), amber (review), watermelon (blocked/loss). Each verdict also gets a shape (square / circle / cross) so meaning is not colour-only. |
| Q4 | MCP tools `audit`, `audit_batch`, `explain`, `trace`. Compact default output, `verbose` flag. Fields-in (calling agent is the OCR). |
| Q5 | Data: UK gov "spend over £25k" (primary, OGL) + USAspending (public domain) + CORD. Fetched once into a pinned snapshot with sha256 manifest. Benchmark runs offline only. |
| Q6 | Full provenance: every finding links to source file, row, sha256, related documents, control text, computation. New forensic controls: Benford, near-duplicate, sequential/reused invoice numbers, currency-aware P-010. |
| Q7 | GitHub Release binaries (win/mac/linux via CI) + `cargo install` + uvx kept + Smithery update + per-agent install docs: Claude Desktop, Claude Code, Cursor, Gemini CLI, Antigravity, Codex, Windsurf, VS Code, ChatGPT (via OpenAPI Action, self-hosted). |
| Q8 | Fully ready, tested and usable publicly tomorrow. |
| Q9 | Offline single-file HTML report (a) + MCP `trace` tool (b) tonight. FastAPI review screen drill-down (c) later. |
| Q10 | Postgres is the history store (Alembic owns the schema, Rust uses the same tables). No-DB = degrade honestly (confirmed). |
| Q11 | `verity mcp --http` for private self-hosting + OpenAPI for GPT Actions. User hosts. No public instance from us. |
| Q12 | Headline framed as two modes: **automatic** (only `blocked` counts as caught) and **assisted** (`blocked`+`review`). Number is **measured, never chosen**: publish whatever comes out (target framing "catches X% fully automatic"), with anomaly categories listed beside it. No tuning toward a target. |
| Q14 | Install unlazy Stop hook for this build; uninstall after release. |
| Q15 | Prepare everything; ask once before push / tag / release. User handles crates.io token, MCP registry DNS TXT, awesome-mcp PR, registrations. |
| Sec | Security and prompt-injection resistance is a ship requirement (see section 5). |

## No-DB behaviour (confirmed)
- Degrade honestly: single-document controls run with no DB. Batch runs use in-batch rows (memory) for history. Cross-run history controls (P-002, P-011, near-dup, sequential no.) read/write Postgres via `DATABASE_URL`. With no URL they emit explicit `not_evaluated` (never a silent pass).

## Execution order (each prefix is a coherent release)
0. **Docs + gates first.** Write `docs/DECISIONS_v1.1.md` (this table + rationale) and `docs/ROADMAP.md` (tonight + post-v1.1) into the repo and the vault folder `C:\Users\Joel Anthony\Documents\Phile\Heafod\Heafod\Verity\`. Write `GATES.md` with runnable `CHECK:`/`EXPECT:` lines. Install the Stop hook. Baseline: `uv run pytest`, `ruff`, `policy_eval`, `fraud_eval` numbers recorded.
1. **Rust core at parity** — new cargo workspace `rust/` with crates `verity-core` (lib: field schema, `PolicyConfig`, 14 policies text, rules, verdict, `normalize_vendor`), `verity-cli` (binary `verity`). Port from `src/verity/policy/{library,rules}.py`. Use `rust_decimal` with Python-matching rounding (ROUND_HALF_EVEN where Decimal default is used). Parity harness: `scripts/parity.py` runs both on examples/, `eval/cases.py`, sample CSVs, real snapshot rows; diff must be empty.
2. **CLI + MCP** — `verity audit <json|csv> [--today] [--profile] [--report out.html] [--json]`, `verity mcp [--http]`. MCP via official `rmcp` crate, stdio default. Compact output e.g. `P-007 blocked: total 1675.00 ≠ 1650.00 (Δ25.00)`. `explain <P-xxx>` returns policy text on demand. `trace <finding_id>` returns provenance links. Postgres via `tokio-postgres` (parameterised), only when `DATABASE_URL` set.
3. **Security** (section 5).
4. **Benchmark** — `scripts/fetch_public.py` (only networked step) to `data/snapshot/` + `MANIFEST.json` (url, sha256, licence, fetched_at). `verity bench` verifies hashes, never networks. Per-dataset profiles (`profiles/uk_spend.toml`, `usaspending.toml`, `cord.toml`): currency, limits, pinned `--today` = dataset period end. Absent fields mapped absent, not zero. UK data is ≥£25k-filtered, so P-009 and splitting are disabled or rescaled there and Benford gets a range/sample-size precondition (fallback last-two-digit test). Metrics: throughput, p50/p99 latency, cold start, tokens per MCP response v1.0 vs v1.1, flag rate, automatic and assisted recall/precision on (i) existing independent `fraud_eval` corpus and (ii) seeded anomalies on real rows incl. types the controls weren't designed around, plus K hand-checked real flags with source links. Output `docs/BENCHMARK.md`, regenerated by one command.
5. **New controls** P-015 Benford (batch), P-016 near-duplicate (fuzzy vendor + amount ε + date window), P-017 sequential/reused invoice number per vendor, P-010 currency-aware. Python mirror for parity. Alembic migration `0004`: `invoice_number`, `currency`, `source_ref` (file,row), `source_sha256` on extractions/audit_runs.
6. **Design** — `assets/` SVG mark, wordmark, social card 1200×630, README hero; `DESIGN.md` with tokens (green, amber, watermelon, neutrals, shape semantics); terminal colours honour `NO_COLOR`.
7. **Installs + release** — CI matrix builds binaries, `cargo test`, `clippy -D warnings`, `cargo audit`, pytest, parity. README rewrite (one-command install, per-agent config blocks). `smithery.yaml` → binary. Versions 1.1.0 in pyproject, `api/main.py`, Cargo. CHANGELOG. Then **ask user** before push/tag/release.

## 5. Security / prompt-injection hardening
- Rust path has no LLM: verdicts are deterministic and cannot be talked out of a finding.
- Strict input schemas (`serde(deny_unknown_fields)`). Caps on string length, line items, batch size, payload bytes.
- Untrusted document text (vendor, item names) returned to agents as quoted, truncated, control-char-stripped data fields, never interpolated into prose or instructions. Tool descriptions static. Output includes `"untrusted_fields"` marker.
- No MCP tool writes files, runs commands, or makes outbound network calls. `cargo tree` gate: core crate has no HTTP client.
- `--http`: binds 127.0.0.1 by default, bearer token required, Origin header validated (DNS rebinding), body size limit.
- HTML report escapes every field, strict CSP, no external resources. CSV export guarded against formula injection (`=,+,-,@` prefix).
- SQL parameterised only. Credentials from env, never argv or logs.
- Python LLM extraction path: extracted text treated as data. Existing `citation_check` stays.
- `cargo audit` + `#![forbid(unsafe_code)]` in core.

## Post-v1.1 roadmap (goes in docs/ROADMAP.md)
PyO3 bindings, delete `rules.py` (single source of truth) · FastAPI review screen drill-down (Q9c) · port API/agent loop pieces where profiling justifies · hosted HTTP instance (optional) · crates.io publish · official MCP registry (`com.uncoalesced/verity`, DNS TXT) · Glama/Smithery/awesome-mcp-servers listings · more datasets (other UK depts, NYC Checkbook) · weekend/holiday dating control · uninstall Stop hook · uncoalesced.com preview refresh with new assets (separate repo).

## Critical files
Port from: `src/verity/policy/rules.py`, `library.py`, `src/verity/extraction/schema.py`, `src/verity/cli.py`, `src/verity/mcp_server.py`. Extend: `src/verity/db/models.py` + `alembic/versions/0004_*`, `src/verity/eval/fraud_eval.py` (reuse for headline), `.github/workflows/ci.yml`, `README.md`, `smithery.yaml`, `pyproject.toml`. New: `rust/`, `scripts/{fetch_public,parity}.py`, `profiles/`, `assets/`, `docs/`, `GATES.md`.

## Verification
- `uv run pytest` (326+ green), `ruff check`, `uv run -m verity.eval.policy_eval` 19/19.
- `cargo test --workspace`, `cargo clippy -- -D warnings`, `cargo audit`.
- `python scripts/parity.py` reports 0 diffs over fixtures + eval cases + all snapshot rows.
- `verity audit examples/*.json` gives PASS / BLOCKED P-002 / BLOCKED P-007.
- MCP smoke: JSON-RPC `initialize` + `tools/call audit` over stdio. Cold start and token count measured.
- Injection tests: vendor = `"Ignore previous instructions… <script>"` stays quoted data in MCP output and is escaped in HTML. `--http` without token returns 401, bad Origin returns 403.
- `verity bench` offline (network disabled) reproduces `docs/BENCHMARK.md` byte-for-byte numbers.
- `node gate-check.mjs GATES.md` all checked.

## Execution notes (what changed from the plan, and why)

- **Controls:** four new controls instead of three. Reused and sequential invoice numbers became separate controls, P-017 (high) and P-018 (low), because one is a hold and the other is a hint.
- **Parity scope:** P-001..P-014 are compared finding-for-finding against the Python engine (17,647 single-document cases including every real row, plus 3,528 real payments through the batch path; 0 differences). The new P-015..P-018 are Rust-only. Mirroring them in Python would be thrown away at the PyO3 step, and the user asked to keep it efficient.
- **MCP implementation:** JSON-RPC is hand-rolled rather than built on `rmcp`. That means a smaller dependency surface, a 1.7 MB binary and a 28 ms cold start. Protocol versions 2025-06-18, 2025-03-26 and 2024-11-05 are accepted.
- **Stop hook:** the unlazy skill ships without its `scripts/` folder, so the Stop hook could not be installed. Gates were run with an equivalent checker instead: 17/17 pass. `GATES.md` is git-ignored.
- **Fixes the benchmark forced:** each was found by hand-checking flags on real data before any number was published.
  - Batch lookback is now anchored to each document's date, not the run date. Before this, historical files lost their duplicate history.
  - P-007 rounding tolerance is per currency. Rupiah receipts rounded to Rp 100 were being flagged.
  - P-016 is high when the supplier and amount are identical within 7 days, which is a resubmitted invoice. Fuzzier matches stay at review.
  - The benchmark runs each anomaly type in isolation, so injections can't mask each other.
- **Headline:** measured, not chosen. Built-for types: 70.4% automatic, 99.7% assisted. All types, including three nothing targets: 48.8% automatic, 69.1% assisted. The 80% figure from the grilling session was not used, because the measurement says something different.
- **Data:** UK figures come from DCMS (two financial years, 2,819 payments after grouping net and VAT lines by transaction number). The GOV.UK CKAN API now redirects to HTML, so the GOV.UK Content API was used instead. USAspending covers NSF FY2025 contracts (709 non-zero actions). CORD v2 labels come from the local HF cache (972 receipts).
- **Python optimisation (Q1, second half):** not started. The Rust core took the time; the pass following `python_refactor.md` is on the roadmap.
- **Name clash:** the Python console script was renamed `verity-py` so `verity` always means the binary.
- **USAspending ids:** `internal_id` identifies the award, not the transaction, and repeats. Rows are now numbered, the award link is kept in `source.url`, and batches with a repeated id are refused.
- **Still the user's to do:**
  - Approve the push, the `v1.1.0` tag and publication of the draft Release.
  - Add the DNS TXT record and run `mcp-publisher` for `com.uncoalesced/verity`.
  - List on Smithery and Glama, and open the awesome-mcp-servers PR.
  - Publish to crates.io (needs a token).
