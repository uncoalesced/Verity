<div align="center">

<img src="assets/verity-banner.svg" alt="Verity" width="100%">

**Verity checks invoices and payments against eighteen written accounts-payable controls and tells you which are fine and which need a person.**
<br>One 1.7 MB binary. No model in the verdict path. Every flag links back to the row it came from.

[![License](https://img.shields.io/badge/license-MIT-1F1F1D?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/core-rust-1F1F1D?style=flat-square)](crates/verity-core)
[![CI](https://img.shields.io/github/actions/workflow/status/uncoalesced/Verity/ci.yml?branch=main&label=CI&style=flat-square&color=7FA650)](https://github.com/uncoalesced/Verity/actions)
[![MCP](https://img.shields.io/badge/MCP-2025--06--18-1F1F1D?style=flat-square)](https://modelcontextprotocol.io)
[![Release](https://img.shields.io/github/v/release/uncoalesced/Verity?style=flat-square&color=7FA650)](https://github.com/uncoalesced/Verity/releases)

</div>

---

## What it does, measured

All of these come from [`docs/BENCHMARK.md`](docs/BENCHMARK.md). One command regenerates it from a hashed, offline snapshot of real public data: UK government payments, US federal contracts and labelled receipts.

| | |
|---|---|
| **Caught automatically**, anomaly types it is built for | **70.4%** blocked with no human involved |
| **Caught with assistance**, same types | **99.7%** raised for a reviewer |
| **Across every injected type**, including three nothing is built to catch | 48.8% automatic, 69.1% assisted, 2,931 cases |
| **Speed** | ~150,000 payments a second on a laptop. MCP cold start 28 ms |
| **Token cost** per MCP audit | 79 to 164 bytes, 90 to 95% less than v1.0 |
| **Rust and Python engines agree** | 0 differences: 17,647 documents one at a time, including every real row, and 3,528 real payments in batch |

Verity is an assistant first. It catches duplicates, resubmissions, split purchases, future-dated documents and documents that don't add up. Out of the box it does not catch an inflated single-line payment or a supplier it has never seen, because nothing on the page gives it anything to check them against. The benchmark breaks this down by type.

It **never pays and never approves**. Pass means no control objected.

---

## Install

**From source with Cargo** (any OS, works today):

```bash
cargo install --git https://github.com/uncoalesced/Verity verity
```

**Prebuilt binaries** for Windows, macOS (Intel and Apple Silicon) and Linux are attached to each [GitHub Release](https://github.com/uncoalesced/Verity/releases). Unpack and put `verity` on your `PATH`.

**Docker:**

```bash
docker run -i --rm ghcr.io/uncoalesced/verity:1.1.0
```

Then:

```bash
verity audit examples/arithmetic_discrepancy.json
```

```
✕ BLOCKED  arithmetic_discrepancy.json  (1 finding)
  P-007 HIGH Arithmetic integrity
    The document states a subtotal of 1500.00 plus tax of 150.00, which comes to 1650.00,
    but the stated total is 1675.00 -- a difference of 25.00. The document does not agree with itself.
```

---

## Use it from your agent (MCP)

Each client below runs the same local binary over stdio. Nothing leaves your machine.

<details open><summary><b>Claude Code</b></summary>

```bash
claude mcp add verity -- verity mcp
```
</details>

<details><summary><b>Claude Desktop</b>: <code>claude_desktop_config.json</code></summary>

```json
{ "mcpServers": { "verity": { "command": "verity", "args": ["mcp"] } } }
```
</details>

<details><summary><b>Cursor</b>: <code>.cursor/mcp.json</code></summary>

```json
{ "mcpServers": { "verity": { "command": "verity", "args": ["mcp"] } } }
```
</details>

<details><summary><b>Windsurf</b>: <code>~/.codeium/windsurf/mcp_config.json</code></summary>

```json
{ "mcpServers": { "verity": { "command": "verity", "args": ["mcp"] } } }
```
</details>

<details><summary><b>VS Code</b> (Copilot agent mode): <code>.vscode/mcp.json</code></summary>

```json
{ "servers": { "verity": { "type": "stdio", "command": "verity", "args": ["mcp"] } } }
```
</details>

<details><summary><b>Gemini CLI</b>: <code>~/.gemini/settings.json</code></summary>

```json
{ "mcpServers": { "verity": { "command": "verity", "args": ["mcp"] } } }
```
</details>

<details><summary><b>Antigravity</b>: Agent panel → MCP Servers → Manage → View raw config</summary>

```json
{ "mcpServers": { "verity": { "command": "verity", "args": ["mcp"] } } }
```
</details>

<details><summary><b>Codex</b>: <code>~/.codex/config.toml</code></summary>

```toml
[mcp_servers.verity]
command = "verity"
args = ["mcp"]
```
</details>

<details><summary><b>ChatGPT</b> (Custom GPT Action, self-hosted)</summary>

ChatGPT can't launch a local program, so it reaches Verity through an HTTPS endpoint you host and keep private:

1. Run the API (`uv run uvicorn verity.api.main:app`) behind HTTPS on your own server.
2. Export its schema: `uv run python scripts/export_openapi.py`.
3. In the GPT editor, add an Action, paste the schema and set API-key authentication.

For MCP clients that only speak HTTP, `verity mcp --http 127.0.0.1:8765` serves the same tools privately. It needs `VERITY_HTTP_TOKEN` (24+ random characters) and rejects any `Origin` not in `VERITY_ALLOWED_ORIGINS`. Put TLS in front of it before exposing it beyond localhost.
</details>

**Tools**

| Tool | What it returns |
|---|---|
| `audit` | Verdict and one line per finding. `verbose: true` for full JSON evidence. `record: true` to write to the Postgres ledger |
| `audit_batch` | Up to 5,000 documents audited against each other, plus a Benford test. Summary plus flagged rows only |
| `explain` | A control's full written policy, only when asked |
| `trace` | Provenance for any finding: the computation, source file, row and sha256, related documents, policy text |

A default `audit` response is the whole of the block below. Policy text, evidence and history only cost tokens when an agent asks for them.

```
BLOCKED run=r1 findings=1
P-007 high: subtotal 1500.00 + tax 150.00 = 1650.00 != total 1675.00 (diff 25.00)
not_evaluated(no history): P-002 P-011 P-016 P-017 P-018
```

---

## Audit a whole file

```bash
verity audit payments.csv --profile profiles/uk_dcms.json --report report.html --csv flagged.csv
```

Verity reads CSV or JSON. It matches column names across common spellings, and a profile maps anything unusual and sets thresholds. You get a terminal summary, an **offline HTML report** and a formula-safe CSV. Each flagged payment in the report opens to show its computation, the policy quoted in full, the source file, row and sha256, and links to the related documents. The report contains no scripts and makes no external requests, and it runs under a strict Content-Security-Policy.

```
# UK DCMS, April 2024 - March 2026 (abridged)
2819 documents  ■ 2110 pass  ● 604 review  ✕ 105 blocked
  P-002 Duplicate payment prevention       67
  P-016 Near-duplicate payment             71
  Benford: nonconformity (MAD 0.0176, n=1688)
audited 2819 documents in 18.6 ms
```

---

## The controls

Every finding cites one of these and quotes it in full. `verity explain P-007` prints any of them.

| ID | Control | Fires when | Verdict |
|---|---|---|---|
| P-001 | Supporting documentation | No readable amount, or a material amount with no supplier and no date | Blocked |
| P-002 | Duplicate payment | Same supplier, amount and date as a document already on file | Blocked |
| P-003 | Supplier identification | No supplier name | Review |
| P-004 | Transaction date | No date | Review |
| P-005 | Late submission | Older than the submission window (90 days) | Review |
| P-006 | Future-dated | Dated after the audit date | Blocked |
| P-007 | Arithmetic integrity | Lines, subtotal, tax and total don't reconcile. Currency-aware rounding | Blocked |
| P-008 | Authorised signature | Over the signature threshold and checked unsigned | Review |
| P-009 | Approval limit | Over the delegated limit | Blocked |
| P-010 | Round amount | Exactly round. Thresholds per currency | Review |
| P-011 | Threshold splitting | Several just-under-limit invoices from one supplier inside 14 days | Blocked |
| P-012 | Approved supplier list | Supplier not on the list (when one is configured) | Blocked |
| P-013 | Low-confidence read | Extraction confidence under 60% | Review |
| P-014 | Intake rejection | File could not be read | Blocked |
| **P-015** | **Benford first digit** | A population's leading digits depart from Benford's law. Truncation-aware | Review |
| **P-016** | **Near-duplicate** | Supplier name variant, amount within 0.5%, dates within 7 days. Same supplier and amount = blocked | Review / Blocked |
| **P-017** | **Reused invoice number** | Same supplier invoice number on two documents | Blocked |
| **P-018** | **Sequential numbering** | A supplier's invoices to you run consecutively | Review |

Controls that need history (P-002, P-011, P-016 to P-018) draw on the other documents in a batch, any `history` you pass, or the Postgres ledger at `DATABASE_URL`. With none of those, they report **not evaluated**, never a silent pass.

---

## Security

Verity sits between untrusted documents and a payment decision, so it treats every document as hostile.

- **Prompt injection.** Verdicts come from code, not a model. No text in a document can argue a finding away. The default MCP output is built only from numbers, ids and dates, so a supplier name written as an instruction never reaches your agent. Verbose output marks document text as data.
- **Strict input.** Unknown fields are rejected, every string and list is capped, and amounts must be plain decimals. Ambiguous input is refused, never guessed at or partly audited.
- **No side channels.** No MCP tool reads or writes files, runs commands or makes network calls. The core crate has no network code and forbids `unsafe`.
- **HTTP mode** binds to localhost, requires a bearer token (compared in constant time), checks `Origin` against an allowlist and caps request size.
- **Outputs.** HTML is escaped under a strict CSP. CSV cells are guarded against formula injection. SQL is parameterised. Credentials come only from the environment and are never logged.

`uv run python scripts/smoke.py security` exercises each of these against the built binary.

---

## Architecture

```
documents ──► (optional) Python extraction: OCR / vision models, FastAPI review queue
                    │  fields as JSON
                    ▼
        ┌────────────────────────────┐
        │  verity-core (Rust)        │   pure functions, no I/O, no clock, no unsafe
        │  18 controls · verdicts    │
        │  Benford · provenance      │
        └────────────────────────────┘
                    │
     verity CLI ─ HTML report ─ MCP (stdio / HTTP) ─ Postgres ledger (optional)
```

The Rust core is the verdict engine. The Python package (`src/verity`) keeps document reading (Donut and YOLOS models), the FastAPI review queue, the agent loop and the evaluation suites. Until the Python side calls the Rust core directly ([roadmap](docs/ROADMAP.md)), `scripts/parity.py` holds the two engines to identical findings on every case.

<details><summary>Python API and extraction setup</summary>

```bash
uv sync
cp .env.example .env
docker compose up -d db
uv run alembic upgrade head        # includes 0004: invoice_number, currency, source_sha256
uv run uvicorn verity.api.main:app --reload
uv run pytest                      # 326 tests
```
</details>

---

## Reproduce every number

```bash
cargo build --release
uv run --with odfpy python scripts/fetch_public.py    # the only networked step; writes a hashed snapshot
verity verify data/snapshot/MANIFEST.json              # offline integrity check
uv run python scripts/parity.py data/snapshot/uk_dcms.json data/snapshot/usaspending.json
uv run python scripts/bench.py                         # writes docs/BENCHMARK.md
```

The snapshot is committed, so everything after `fetch_public.py` runs with the network off.

**Honest limits.** The benchmark's anomalies were injected by the same project that wrote the controls. That is why the types no control was designed for sit in the headline, and why the false-alarm rate on untouched data is published next to it. On real government data, most review flags are round grant payments (P-010). The duplicate pairs it holds are same-supplier, same-amount, same-day payments that a person should confirm. They are not proven errors. On genuine receipts, P-007 raises 9.3% of undiscounted ones. Open them with `verity audit data/snapshot/cord.json --profile profiles/cord.json --report cord.html` and judge for yourself. Document reading (the Python extraction path) is far less accurate than the controls. See `fraud_eval --source images`.

---

## Data and licences

Code: MIT. Benchmark data: contains public sector information licensed under the [Open Government Licence v3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/) (UK DCMS). USAspending.gov data (public domain). CORD v2 labels, CC BY 4.0 (Park et al., 2019).

<div align="center"><sub>Engineered by <a href="https://github.com/uncoalesced">uncoalesced</a> · <a href="docs/ROADMAP.md">Roadmap</a> · <a href="DESIGN.md">Design</a> · <a href="CHANGELOG.md">Changelog</a></sub></div>
