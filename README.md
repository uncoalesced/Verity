<div align="center">

```
██╗   ██╗███████╗██████╗ ██╗████████╗██╗   ██╗
██║   ██║██╔════╝██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
╚██╗ ██╔╝█████╗  ██████╔╝██║   ██║    ╚████╔╝ 
 ╚████╔╝ ██╔══╝  ██╔══██╗██║   ██║     ╚██╔╝  
  ╚═══╝  ███████╗██║  ██║██║   ██║      ██║   
         ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   
```

# Verity `v1.0`
> **Engineered by [uncoalesced](https://github.com/uncoalesced).**  
> Deterministic Pre-Payment Accounts Payable Auditor & Policy Engine.

[![License](https://img.shields.io/badge/license-MIT-black?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-black?style=flat-square)](https://python.org)
[![CI](https://img.shields.io/github/actions/workflow/status/uncoalesced/Verity/ci.yml?branch=main&label=CI&style=flat-square&color=black)](https://github.com/uncoalesced/Verity/actions)
[![MCP Spec](https://img.shields.io/badge/mcp%20spec-2024--11--05-black?style=flat-square)](https://modelcontextprotocol.io)
[![Smithery](https://img.shields.io/badge/smithery-verity-black?style=flat-square)](https://smithery.ai)
[![Glama](https://img.shields.io/badge/glama-listed-black?style=flat-square)](https://glama.ai)

</div>

---

## Deterministic Contract Boundary

Verity enforces a strict architectural boundary between probabilistic document ingestion (OCR, vision models, LLMs) and statutory accounts-payable controls. Financial disbursements and audit findings must **never** depend on non-deterministic model mood or hallucinations.

```text
[ Untrusted Ingestion / OCR / LLM ]
                │
                ▼ (JSON payload)
┌────────────────────────────────────────┐
│  VERITY DETERMINISTIC BOUNDARY         │
│  ├── 1. Arithmetic & Cross-Field Gate  │
│  ├── 2. Historical Duplicate Detection │
│  ├── 3. Currency / Threshold Rulebook  │
│  └── 4. Tamper-Evident Override Trail  │
└────────────────────────────────────────┘
                │
                ▼
[ Pass / Policy Violation Exception ]
```

Verity reads invoices and receipts, checks each one against 14 written accounts-payable controls, and sorts documents into three distinct states: **clear** (passes automatically), **hold for review**, or **block**.

It **never** pays and **never** approves. It performs the audit pass and leaves every judgement call to a named reviewer with an append-only audit trail.

---

## Instant Execution (`uvx` / Zero Friction)

Run Verity directly from GitHub without cloning or local setup:

```bash
# Audit a JSON fixture or document against all 14 statutory controls:
uvx --from git+https://github.com/uncoalesced/Verity verity audit examples/clean_invoice.json

# Launch the Model Context Protocol (MCP) server over stdio:
uvx --from git+https://github.com/uncoalesced/Verity verity-mcp
```

---

## Golden Test Fixtures (Proof of Determinism)

Verity guarantees reproducible, mathematical evaluation where LLMs fail to catch subtle arithmetic or ledger state leaks. Three standard fixtures are provided under [`examples/`](examples/):

### 1. Statutory Clean Invoice (`examples/clean_invoice.json`)
Passes all 14 AP controls: matching subtotal + tax = total, valid vendor, non-stale date, authorised signature, and legitimate non-round amounts.

```bash
$ uv run verity audit examples/clean_invoice.json
======================================================================
VERITY DETERMINISTIC AUDIT REPORT
======================================================================
Target:    examples/clean_invoice.json
Vendor:    Acme Industrial Supplies Ltd
Date:      2026-10-25
Total:     1425.50
Verdict:   PASS
Severity:  NONE
Findings:  0 policy violation(s)
----------------------------------------------------------------------
Status: All 14 statutory AP controls satisfied. No exceptions.
======================================================================
```

### 2. Historical Duplicate Detection (`examples/duplicate_vendor_hash.json`)
Catches identical vendor, amount, and date matches against the 6-month historical database (Control **P-002**):

```bash
$ uv run verity audit examples/duplicate_vendor_hash.json
======================================================================
VERITY DETERMINISTIC AUDIT REPORT
======================================================================
Target:    examples/duplicate_vendor_hash.json
Vendor:    Acme Industrial Supplies Ltd
Date:      2026-10-25
Total:     1425.50
Verdict:   BLOCKED
Severity:  HIGH
Findings:  1 policy violation(s)
----------------------------------------------------------------------
[HIGH] P-002: Duplicate payment prevention
Reason: Matches document #1042 on supplier, amount (1425.50) and date (2026-10-25). Held pending confirmation that the two are distinct.
Policy: "The same invoice must not be paid twice. An invoice matching a previously submitted document on vendor, amount and date is treated as a duplicate and held from payment until a reviewer confirms the two are genuinely distinct."
======================================================================
```

### 3. Arithmetic Discrepancy Gate (`examples/arithmetic_discrepancy.json`)
A subtle subtotals + tax rate mismatch ($1,500.00 subtotal + $150.00 tax = $1,650.00, but stated total is $1,675.00) that LLMs consistently overlook. Caught and blocked deterministically by Control **P-007**:

```bash
$ uv run verity audit examples/arithmetic_discrepancy.json
======================================================================
VERITY DETERMINISTIC AUDIT REPORT
======================================================================
Target:    examples/arithmetic_discrepancy.json
Vendor:    Apex Logistics Corp
Date:      2026-10-28
Total:     1675.00
Verdict:   BLOCKED
Severity:  HIGH
Findings:  1 policy violation(s)
----------------------------------------------------------------------
[HIGH] P-007: Arithmetic integrity
Reason: The document states a subtotal of 1500.00 plus tax of 150.00, which comes to 1650.00, but the stated total is 1675.00 -- a difference of 25.00. The document does not agree with itself.
Policy: "The line items on a document must reconcile to the stated total within tolerance. A total that exceeds the sum of its lines is the most common form of altered-document fraud and is escalated for manual inspection."
======================================================================
```

---

## MCP Registries & Client Setup

Verity runs as an MCP stdio server that exposes the `audit_document` tool to Claude, Cursor, Windsurf, Codex, and any MCP-compliant agent.

### 1. Claude Code & Claude Desktop Configuration
Add to your `claude_desktop_config.json` or project MCP settings:

```json
{
  "mcpServers": {
    "verity": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/uncoalesced/Verity", "verity-mcp"],
      "env": {
        "VERITY_API_URL": "http://127.0.0.1:8000"
      }
    }
  }
}
```

### 2. Cursor (`.cursor/mcp.json`)
Add to your project's `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "verity": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/Verity", "verity-mcp"],
      "env": {
        "VERITY_API_URL": "http://127.0.0.1:8000"
      }
    }
  }
}
```

### 3. Smithery (`smithery.ai`)
Verity includes a root [`smithery.yaml`](smithery.yaml) for automated indexing and one-click installs:

```bash
npx -y @smithery/cli install verity --client claude
```

### 4. Official MCP Registry & Registries
- **Official MCP Registry**: Registered under reverse-DNS `com.uncoalesced/verity` via DNS TXT verification.
- **Glama**: Indexed at [glama.ai/mcp/servers](https://glama.ai).
- **Awesome MCP Servers**: Catalogued in community registries under *Finance & Security*.

---

## The Fourteen Controls

Every single finding traces back to one of these written controls. Verity quotes the full verbatim policy wording on the finding, never a summary or model hallucination.

| ID | Control | What it looks for | Outcome |
|---|---|---|---|
| **P-001** | Supporting documentation required | No amount read, or sizeable amount without legible supplier and date | Blocked |
| **P-002** | Duplicate payment prevention | Matching supplier, amount, and date against 6-month historical database | Blocked |
| **P-003** | Supplier identification | Missing legible supplier or merchant name | Review |
| **P-004** | Transaction date required | Missing transaction or supply date | Review |
| **P-005** | Late submission | Document older than submission window (default 90 days) | Review |
| **P-006** | Future-dated documents | Document date post-dates current audit date | Blocked |
| **P-007** | Arithmetic integrity | Line items, subtotal, and tax do not reconcile to total within tolerance (0.05 / 35% mark-up) | Blocked |
| **P-008** | Authorised signature | Document exceeds signature threshold ($2,500) without visible signature/stamp | Review |
| **P-009** | Delegated approval limit | Total exceeds organisation sign-off limit ($10,000) | Blocked |
| **P-010** | Round-amount anomaly | Suspiciously exact round amounts (step/floor advisory) | Review |
| **P-011** | Threshold avoidance by splitting | Multiple near-limit invoices from same supplier within splitting window (14 days) | Blocked |
| **P-012** | Approved supplier list | Supplier not on organisation's approved vendor list (when configured) | Blocked |
| **P-013** | Low-confidence extraction | Extraction model confidence below minimum threshold (default 60%) | Review |
| **P-014** | Intake rejection | Unreadable, corrupt, blank, password-protected, or unsupported format | Blocked |

*Note*: If **P-014** fires, intake is rejected immediately and the other 13 controls do not evaluate.

---

## What a Held Document Actually Looks Like

Take a real example: a supplier invoice for $4,820.75, with no signature anywhere on the page. That sits above the $2,500.00 signature threshold, so **P-008** fires:

> Authorised signature. Amount 4820.75 is above the 2500.00 signature threshold and no signature or stamp was found on the document.
>
> *"Documents above the signature threshold must carry a visible authorising signature or company stamp. Unsigned high-value documents are held pending evidence of authorisation."*

The first line explains what was detected on the document. The second line quotes the governing policy text verbatim as it existed at the time of the audit, bound permanently to the audit record.

---

## Default Policy Thresholds

These settings are owned and configurable by the finance team without touching source code:

| Setting | Default | What it governs |
|---|---|---|
| Receipt required above | $75.00 | Below this, missing receipt isn't flagged. Above it, missing supplier/date trips P-001 |
| Signature required above | $2,500.00 | Documents above this require visible authorising signature or stamp (P-008) |
| Approval limit | $10,000.00 | Sign-off ceiling requiring escalation (P-009); splitting baseline (P-011) |
| Arithmetic tolerance | 0.05 | Reconciling line items to stated subtotal and total (P-007) |
| Maximum mark-up | 35% | Plausible tax/service gap before flagging arithmetic mismatch (P-007) |
| Submission window | 90 days | Invoices older than this are flagged as late (P-005) |
| Splitting window | 14 days | Proximity window for multiple near-limit invoices (P-011) |
| Splitting proximity | 90% | Invoices >= $9,000 (90% of $10,000 limit) evaluated for splitting (P-011) |
| Minimum extraction confidence | 60% | Below this, sent for manual review regardless of content (P-013) |
| Approved supplier list | Disabled | Enabled once organization populates approved vendor list (P-012) |

---

## Period Auditing & Reporting

Point Verity at an inbox folder to audit an entire period close at once:

```bash
uv run scripts/audit_folder.py ./inbox --out exceptions.csv --save
```

- **`--out exceptions.csv`**: Produces an actionable spreadsheet of every held or blocked invoice with policy citations.
- **`--save`**: Persists records to PostgreSQL, updating the 6-month historical database to enable duplicate detection (**P-002**) and threshold splitting (**P-011**).
- **Audit Pack (`GET /runs/{run_id}/pack`)**: Generates the complete, defensible evidentiary dossier for internal/external auditors.

---

## Engineering Setup & Execution

### Prerequisites
- Python 3.11+ managed via [`uv`](https://github.com/astral-sh/uv).
- PostgreSQL 16 with `pgvector` (`pgvector/pgvector:pg16` via `docker-compose.yml`).
- SQLite in-memory supported for testing without database dependencies.

```bash
# Setup dependencies & environment
uv sync
cp .env.example .env
docker compose up -d db

# Run database migrations
uv run alembic upgrade head

# Start FastAPI application
uv run uvicorn verity.api.main:app --reload

# Start MCP stdio server
uv run verity-mcp
```

### Key API Endpoints
| Endpoint | Method | Purpose |
|---|---|---|
| `/documents` | `POST` | Upload file (multipart), run full audit pipeline, store result |
| `/audit` | `POST` | JSON audit endpoint (`content_base64` or pre-extracted `fields`) |
| `/runs` | `GET` | Review queue with period summary statistics |
| `/runs/{run_id}` | `GET` | Complete run record including execution trace |
| `/runs/{run_id}/pack` | `GET` | Defensible audit pack with verbatim policy citations |
| `/runs/{run_id}/review` | `POST` | Record named human reviewer decision (approve / reject / info) |
| `/reports/exceptions.csv` | `GET` | Download period exception CSV report |

### Deterministic Test & Evaluation Suite

Run the full automated test suite and deterministic benchmarks:

```bash
# Run 326 unit and integration tests
uv run pytest

# Code style and linting
uv run ruff check src tests scripts

# Deterministic Evaluation Suites (Zero external keys required)
uv run -m verity.eval.policy_eval                                    # 14 controls across 19 baseline cases
uv run -m verity.eval.fraud_eval --corpus sample/verity_sample_invoices_m_500.csv   # Held-out fraud evaluation
uv run -m verity.eval.trajectory_eval                                # State-machine agent routing fidelity
uv run -m verity.eval.rag_eval --corpus sample/verity_sample_invoices_m_500.csv     # Policy search retrieval benchmarks
uv run -m verity.eval.extraction_eval --limit 25                     # OCR/extraction benchmarks (CORD/SROIE)
```

---

## Measured Benchmark Caveats & Operational Profile

We publish exact benchmark observations rather than generic accuracy claims:

1. **Extraction Accuracy**: Document totals are extracted reliably (F1 ~0.979 on CORD benchmark), but individual line items are noisier (F1 ~0.690), making P-007 sensitive on degraded physical scans.
2. **Confidence Calibration**: The 60% threshold for P-013 is an uncalibrated default; raw model confidence does not reliably correlate with ground-truth extraction on degraded scans.
3. **Scanned vs Digital PDFs**: Verity is designed for scanned receipts and paper invoices. Born-digital PDFs without raster images fail intake (P-014) rather than guessing.
4. **Multi-Currency**: Round-amount anomaly (P-010) is currently currency-agnostic.
5. **History Requirement**: P-002 and P-011 require DB persistence enabled (`--save` or API `db_history`) with a 6-month lookback window.

---

## License

MIT License. Engineered by [uncoalesced](https://github.com/uncoalesced).
