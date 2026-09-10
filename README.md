# Verity

Verity reads invoices and receipts, checks each one against a written set of accounts-payable controls, and tells you which ones are fine and which ones need a person. It does not pay anything, and it does not approve anything. It reads, it checks, and it holds up its hand.

## The problem this is for

Somewhere in most finance functions, someone is opening PDFs and photographs of receipts one at a time, checking whether the total adds up, whether there's a signature on the big ones, whether this invoice looks suspiciously like one that was already paid last month. It's tedious, it's easy to get wrong when you're doing your fortieth one of the day, and the things that slip through — a duplicate payment, an invoice quietly split into two so it clears under someone's approval limit — are exactly the things an auditor asks about later.

Verity does the first pass of that work. A person still makes every judgement call; Verity just makes sure the obvious checks happen on every document, every time, and writes down why.

## What it actually does

For each document, Verity:

1. Reads it: supplier, date, amount, the line items, whether it's signed.
2. Checks it against fourteen written controls (below).
3. Reaches one of three outcomes: **clear it**, **hold it for review**, or **block it**.

That's the whole job. Verity never releases a payment itself. When it holds or blocks something, a named person has to look at it and decide — approve, reject, or ask for more information. If that person overrides a block and lets the payment through anyway, that's recorded explicitly as an override, not quietly folded into "approved." Six months later, when someone asks why a particular invoice went out, the answer is on file: what the document said, which control had a problem with it, and who decided to proceed regardless.

Every single thing Verity flags comes with the exact wording of the policy it's checking against, quoted in full rather than paraphrased. Nothing is held because a model "seemed unsure" or "looked odd." If you can't find the sentence that justifies a hold, something is wrong with the system, not with the document.

Different people in a finance function will touch different parts of this. A controller sets and owns the thresholds. An accounts-payable manager lives in the review screen and the exception report, clearing the queue day to day. A head of internal audit, or an external auditor at year end, wants the audit pack — the full, quoted record for one document, or for a whole period.

## Following one document through the system

1. **Can this even be opened?** Right format, not corrupt, not blank, not password-protected. A file fails this check when it's not a PDF or a recognised image type, when it won't decode at all, when a PDF is password-protected, or when the page is effectively blank — no visible content to read. A file that fails here never gets scored. It's reported as unreadable, which is treated as an open item requiring a person's attention, not as a document that quietly passed.
2. **Get a readable page.** This works for a scan or a photograph of a document. A born-digital PDF — one produced straight out of accounting software, with no picture of a page inside it — cannot be turned into an image yet, and is reported as unreadable rather than guessed at. See Limitations below.
3. **Read the document.** Supplier, date, total, the line items, a subtotal if there is one. Verity also produces its own confidence score for how sure it is of that reading.
4. **Look for a signature or stamp** on the page. This runs on every document; it is the control at step 6 that decides whether the absence of one actually matters, based on the amount.
5. **Check against what's already on file**, which is how the duplicate-payment and invoice-splitting controls work. The lookback is six months.
6. **Run all fourteen controls.** This last step involves no reading and no external system — same document, same settings, same answer, today or at an audit two years from now.

If the model or system behind step 3 or 4 genuinely breaks (a service is down, say), Verity does not report that as a bad document. It stops and says so plainly. Calling an infrastructure failure a document problem would be its own kind of misleading answer.

## The fourteen controls

Every finding traces back to one of these. The wording below is a plain-language summary; the system quotes the full policy text on the finding itself, not this summary.

| ID | Control | What it looks for | Outcome |
|---|---|---|---|
| P-001 | Supporting documentation required | No amount could be read at all, or a sizeable amount with neither a supplier name nor a date anywhere on the document | Blocked |
| P-002 | Duplicate payment prevention | Same supplier, same amount, same date as a document already on file | Blocked |
| P-003 | Supplier identification | No legible supplier or merchant name on the document | Review |
| P-004 | Transaction date required | No date for when the goods or services were supplied | Review |
| P-005 | Late submission | Document is older than the submission window (90 days by default) | Review |
| P-006 | Future-dated documents | Document is dated after today — usually a transposed or fabricated date | Blocked |
| P-007 | Arithmetic integrity | The line items don't reconcile to the stated total or subtotal, beyond a small rounding tolerance | Blocked |
| P-008 | Authorised signature | No visible signature or stamp on a document above the signature threshold | Review |
| P-009 | Delegated approval limit | Amount exceeds what can be approved without escalation. Verity routes this upward — it does not approve it | Blocked |
| P-010 | Round-amount anomaly | Amount is suspiciously exact (a round hundred or more). Not proof of anything on its own, just worth a second look | Review |
| P-011 | Threshold avoidance by splitting | Two or more invoices from the same supplier, close together in time, each sitting just under the approval limit | Blocked |
| P-012 | Approved supplier list | Supplier is not on your approved list. Only active once your team has actually configured a list | Blocked |
| P-013 | Low-confidence extraction | Verity could not read the document with enough confidence to trust its own answer | Review |
| P-014 | Intake rejection | The file itself couldn't be opened — corrupt, blank, password-protected, or an unsupported format | Blocked |

The rule is simple: if anything serious fires, the document is **blocked** and the payment is held until someone decides. If something less serious fires but nothing serious does, it's sent for **review**. A document with nothing flagged at all **passes** automatically. A document rejected at intake (P-014) never reaches the other thirteen controls, because nothing was read, so nothing else has anything to comment on.

## What a held document actually looks like

Take a real example: a supplier invoice for 4,820.75, with no signature anywhere on the page. That's above the signature threshold, so P-008 fires, and the finding a reviewer sees reads:

> **Authorised signature.** Amount 4820.75 is above the 2500.00 signature threshold and no signature or stamp was found on the document.
>
> *"Documents above the signature threshold must carry a visible authorising signature or company stamp. Unsigned high-value documents are held pending evidence of authorisation."*

The first line is what happened on this specific document. The second, in italics, is the policy wording itself, copied onto the finding exactly as it stood at the time, not a link to a policy that might since have been edited. That's what "cites a written policy" means in practice: a reviewer, or an auditor two years later, can read the sentence Verity was enforcing without having to go and find the current version of anything.

A document can trip more than one control at once (an invoice can be both unsigned and suspiciously round), and every one of them shows up the same way, worst first.

## The numbers that decide the outcome

These are not fixed in the software. They're settings your finance team owns and can change without anyone touching code. The values below are the defaults Verity ships with.

| Setting | Default | What it governs |
|---|---|---|
| Receipt required above | 75 | Below this, a missing receipt isn't flagged. Above it, a document with no supplier and no date trips P-001 |
| Signature required above | 2,500 | Above this amount, a document needs a visible signature or stamp (P-008) |
| Approval limit | 10,000 | Above this, an expense needs sign-off at the next level (P-009), and it's the reference point for the splitting check (P-011) |
| Arithmetic tolerance | 0.05 | How far the line items can miss the stated total before it counts as a mismatch (P-007) |
| Maximum explainable mark-up | 35% | How far above the line items a total can sit before the gap stops looking like tax or a service charge (P-007) |
| Submission window | 90 days | Documents older than this are flagged as late (P-005) |
| Splitting window | 14 days | How close together two near-limit invoices from the same supplier need to be before they're reviewed together (P-011) |
| Splitting proximity | 90% of the approval limit | How close to the limit an invoice has to sit to count as "just under" for the splitting check |
| Minimum reading confidence | 60% | Below this, the document goes to a person regardless of what else it shows (P-013) |
| Approved supplier list | Off (empty by default) | Switches on only once your team supplies a list of approved suppliers (P-012) |

Whatever these are set to when a document is audited gets stored with that document's record, permanently. If you raise the approval limit next quarter, an audit from this quarter still shows the limit that was actually in force at the time. Nobody has to reconstruct what the rules used to be.

One control isn't in this table yet: the round-amount check (P-010) has a fixed floor and step size written into the code rather than a setting your team can change, and it doesn't distinguish between currencies. See Limitations.

## Auditing a whole period at once

For a period close, point Verity at a folder containing every invoice and receipt for the period. It works through the folder document by document, applying the same fourteen controls to each one, and gives you back:

- a count of how many cleared, how many need a look, and how many are blocked, broken down by which control fired and how often;
- a spreadsheet (CSV) listing everything that needs a person, ready to open in Excel and work through.

One broken or unreadable file does not stop the batch. The rest of the folder still gets audited, and the failure on that one document is recorded rather than silently dropped. A batch that gives up on document 40 of 200 is worse than useless, because it looks like it finished.

## What gets kept, and why an old decision still makes sense later

Every audit is stored complete, not summarised down to a verdict:

- the fields Verity actually read off the document;
- every control that fired, with its title and the full policy wording it fired under, quoted rather than paraphrased;
- the settings that were in force at the time;
- a step-by-step record of what the system did to reach its answer.

When a person releases, rejects, or asks for more information on a held document, that decision is recorded against their name, with their reasoning if they gave one. Decisions are never edited or deleted — only added to. If someone later overturns an earlier decision, both sit in the record, in order. And if a person clears a document the controls had blocked, that's flagged explicitly as an override. That single flag is usually the most useful line in the whole file: the controls said no, and a named person said yes anyway.

## Getting the work out to people who don't use the system

Two outputs exist for this, and neither is clever. A reporting layer that's clever is how two views of the same numbers stop agreeing with each other.

**The exception report** is a CSV of everything currently held: one row per document, with the controls that fired, the amount, the supplier, and whether (and by whom) it's been looked at. Hand it to an accounts-payable manager who has never opened Verity's screen and never needs to.

**The audit pack** is the same information, assembled for one document at a time, in full, in the order an external auditor would want to read it: verdict, every control that fired with its policy text, the fields that were read, the settings that were in force, and the full reviewer history. This is what goes in the file when someone asks how a payment came to be released.

## The review screen

A simple web page shows the queue: how many are clear, how many need review, how many are blocked, and how many have already been overridden by a reviewer. Click into any held document to see what was read and which controls fired, each with its policy wording attached. There are three buttons: approve, reject, ask for more information. A reviewer has to type their name before any of them does anything; a decision with no name against it is refused outright.

## What this does not do well yet

We'd rather you heard this from us than found it out during a close.

The controls have now been checked two ways, and the difference between them matters.

The first way is nineteen example cases we wrote ourselves, one or more for every control. They score a perfect match on all nineteen. That tells you the logic does what we designed it to do — but the same people wrote the control and the case, so it is a check on our own reasoning, not evidence about your invoices.

The second way is a set of 500 invoices with problems deliberately planted in them, labelled by someone other than the person who wrote the controls. Forty carry a planted problem. Thirty of those forty are the kind of problem one of our controls exists to catch, and **Verity caught all thirty**. Across those thirty, one clean document was flagged by mistake — a bill that happened to land on an exactly round number, which is the round-amount check doing what it is designed to do rather than a bug. None of the other 460 legitimate invoices tripped a fraud control.

Two things to hold onto about that number before you lean on it:

**Ten of the forty planted problems, Verity cannot catch at all.** Three were invoices quoting a purchase-order number that doesn't correspond to a real open order, and seven were invoices submitted at odd hours with no prior pattern for that supplier. Verity has no purchase-order data and never sees when a document was submitted, so no control covers either. Most of those ten were flagged anyway, but for a different reason — usually the approval limit — which is not the same as catching them. If purchase-order matching is central to how you control spend, Verity does not do it today.

**That test hands Verity the numbers rather than making it read them.** It measures the controls, not the reading, and those fail in different ways. We also ran the harder version: the same invoices printed as pages, put through the whole system with nothing handed to it. That result is much worse, and it is the one to plan around.

On 25 printed invoices, Verity flagged something on every single one, including all 22 that were perfectly legitimate. It read the supplier name wrongly often enough that all 25 looked like suppliers not on the approved list, and it misread the arithmetic on 15. Of the three planted problems in that batch it caught two. In plain terms: **hand it a picture rather than a spreadsheet and, today, the queue it produces is mostly noise.** The reading step is the bottleneck, not the controls — the same controls scored near-perfectly when the numbers were correct.

That result is not an artefact of how the pages are drawn. The renderer prints no signature on any page, so the signature check (P-008) is switched off for this run rather than left to fire on all 25 — it never appears among the controls that fired. Every finding counted above came from a control reading the numbers on the page: the supplier check (P-012) on all 25, the arithmetic check (P-007) on 15, the approval limit (P-009) on 16, and supporting documentation (P-001) on 6.

One further thing, and it is the one we would most want a finance team to know. Verity reports a confidence score for each reading, and holds anything below a threshold for a person. On those 25 printed pages it reported an average confidence of 95% while getting 8% of them right. **The confidence score is not currently a reliable signal of whether a reading is correct**, so do not treat a high-confidence read as a checked one, and do not raise that threshold expecting it to filter out bad readings. Stated as an open item rather than a caveat: the 60% minimum-confidence threshold behind P-013 is not validated by any calibration evidence we currently hold, and should be treated as an untuned default. We measure this deliberately (`uv run -m verity.eval.trajectory_eval --calibration ...`) so it stays visible rather than becoming a surprise.

Two of the fourteen, duplicate payment prevention (P-002) and threshold-avoidance splitting (P-011), can only catch anything if Verity has a history of prior documents to compare a new one against. Both the web upload and the folder audit now build that history for you, so a genuine duplicate is caught. Two things follow from how it works. The folder audit only builds a history when you ask it to save its results; run it in preview mode and it will tell you, on the way past, that those two controls cannot fire. And the comparison only reaches back six months, so a duplicate of something older than that will not be spotted.

Reading accuracy is the weakest part of the system, and worth being precise about. Measured against a public benchmark of 25 scanned receipts:

| What was read | Got it right, of the ones it claimed | Found, of the ones that were there |
|---|---|---|
| The total | 100% | 96% |
| Individual line items | 67% | 71% |

Read that as: when Verity reports a total, it has so far always been the right total, and it found the total on 23 of the 24 receipts that had one. Line items are much rougher. Roughly a third of the individual lines it reports are wrong or spurious, and it misses about three in ten.

That matters less than it first appears, because of what the totals are used for. The arithmetic check (P-007) compares the lines against the stated total, so poor line reading makes that control noisier, not silently wrong. The amount that drives the approval limit, the signature threshold and the duplicate check is the total, and that is the number being read most reliably.

For context on the direction of travel: an earlier version of the reading step scored 71% on totals and 10% on line items, because it could only ever return a single line from a multi-line receipt. Reading the whole document in one pass instead is what moved those numbers.

Two things this measurement does not tell you. It is 25 receipts from a public research dataset, not your suppliers' invoices, and receipts in a benchmark are cleaner than what lands in a real inbox. And supplier name and transaction date are not scored at all above, because that dataset does not label them. They are read by a separate, weaker step, and we currently have no measured accuracy figure for either.

Supplier name and transaction date come from a different, weaker reading step than the amount and line items, and they're less reliable. Expect to correct them more often than the total.

Verity reads scanned documents — a photograph or scan of a paper invoice. Digital PDFs generated directly by accounting or invoicing software, with no picture of a page inside them, aren't supported yet. Today's version can't produce a readable page from one and reports it as unreadable rather than guessing.

The round-amount check doesn't know what currency it's looking at — an amount of exactly 500 looks the same to it whether that's dollars, euros, or rupiah. If your organisation transacts in more than one currency, treat that particular control as advisory until it's made currency-aware.

Searching the policy library is weaker than the controls that use it. If you type a problem into the search box in your own words — "the total doesn't match the subtotal plus tax" — the right policy comes back first about 4 times in 10, and somewhere in the top three about 7 times in 10. One control, the threshold-splitting check, never comes back at all for a plain-English description of what it does. This does not affect what Verity catches: every control runs on every document regardless of what search returns. It affects how easily a reviewer can look up why something was flagged. Those two figures are hit@1 (0.433) and hit@3 (0.733), with an MRR of 0.561, counted by `rag_eval`'s own keyless retrieval metric against the control each note is labelled with — they are not RAGAS scores. RAGAS faithfulness and context precision need a live API key and have never been run, so we have no RAGAS number to quote.

There is now an optional second opinion on the wording of a finding. After the controls have decided, Verity can ask Claude whether the policy passage quoted on a finding genuinely supports what the finding claims — a check on our own control library, since the controls quote their own policy and would go on agreeing with themselves even if one cited the wrong rule. It is off unless you configure it, it costs a fraction of a penny per finding, and it cannot change a verdict or release a payment. If it flags something, that is a note for whoever maintains the policy wording, not a reason to pay an invoice we held. We have built and tested this against fixed replies; it has not yet been run at volume against live documents, so we have no accuracy figure for it to quote you.

Nobody has yet run this against a real company's ledger. Everything above is measured against test documents and planted examples. Before relying on Verity for an actual period close, run it alongside your existing process for at least one full period and compare the two before trusting it on its own.

## For your engineering team

Setup:

```bash
uv sync
cp .env.example .env
docker compose up -d db
uv run alembic upgrade head
uv run uvicorn verity.api.main:app --reload
```

Postgres is only needed for persistence and the review screen's history. The evaluation commands below, and a dry run of the batch script without `--save`, don't touch the database.

The test suite builds its schema on in-memory SQLite, so for a while migrations `0002` (audit runs, findings, trace steps) and `0003` (review decisions) had only ever run there. On 10 September 2026 all three migrations were applied to a live Postgres 16 (`docker compose up -d db`, then `uv run alembic upgrade head`) and every table was then written to and read back through the API — an upload, a reviewer decision recorded against it, and a JSON audit — so the mapping, not just the DDL, has been exercised on a real database. Note that `0001` creates the `vector` extension, so this needs the `pgvector/pgvector:pg16` image that `docker-compose.yml` specifies; a stock `postgres:16` fails on that line. Nothing pending needs a *new* migration — `AuditRun.fields` is JSON, which is why adding the `tax` field required none.

Auditing a folder from the command line:

```bash
uv run scripts/audit_folder.py ./inbox --out exceptions.csv
```

Add `--save` to persist every run to the database; without it, this only writes the CSV.

The duplicate-payment and splitting checks need prior documents to compare against. Both entry points wire that up: the API binds `verity.agent.history.db_history(session, exclude_document_id=...)` per request, and the batch script binds it when `--save` is passed. `db_history` deliberately takes the caller's `Session` rather than a factory, so the lookup runs inside the same transaction as the intake record it is about. If you add a third entry point, use `verity.agent.tools.with_history` to bind it — a `Toolbox` left at the default `history` silently makes both controls dead.

Key API endpoints, once the server is running:

| Endpoint | Purpose |
|---|---|
| `POST /documents` | Upload one file, run it through the full audit, store and return the result |
| `POST /audit` | The same audit, sent as JSON rather than a form. This is the one an outside agent calls — see below |
| `GET /runs` | The queue, with a period summary |
| `GET /runs/{run_id}` | One run in full, including the trace |
| `GET /runs/{run_id}/pack` | The audit pack for that run |
| `POST /runs/{run_id}/review` | Record a reviewer's decision |
| `GET /reports/exceptions.csv` | The exception report |
| `GET /policies` | The control library, as the API sees it |

### Calling Verity from another agent

Verity has a second job besides its own review screen: being the thing a coding or finance agent calls when it has an invoice and needs a defensible answer about it. Two integration paths cover the five agent products people ask about, and neither of them moves any policy logic out of the server — the agent sends a document, the same fourteen controls run, and the answer comes back with the policy wording quoted on every finding, exactly as the review screen gets it.

Both paths go through `POST /audit`, which takes one document as JSON in either of two forms, exactly one per request: `content_base64` is the file itself and Verity reads it, which needs the extraction models on the server; `fields` is a reading the agent already did, which skips the models entirely and applies the controls to the numbers as given. `POST /documents` is unchanged and still there for the browser form — same audit, same stored row, the bytes just arrive differently.

One thing to read carefully in the answer: on a `fields` request, the confidence score that comes back is *the caller's own*, handed straight through. It is not Verity's assessment of a reading it did not do. And a `pass` means no control objected — it is never an instruction to pay anything.

**Path one, MCP.** Claude, Gemini CLI, Cursor and Codex all speak the Model Context Protocol, so one server covers four of the five.

```bash
uv run uvicorn verity.api.main:app          # the API, in one terminal
uv run verity-mcp                           # the MCP server, over stdio
```

The MCP server is a client of the API, not a second copy of it. It does not start one, and it needs `VERITY_API_URL` to point at a running instance (default `http://127.0.0.1:8000`). It exposes exactly one tool, `audit_document`. There is no manifest file: an MCP client is configured by adding an entry to its own config, which for a stdio server means the command to run and any environment it needs. In the shape almost every client uses:

```json
{
  "mcpServers": {
    "verity": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/verity", "verity-mcp"],
      "env": { "VERITY_API_URL": "http://127.0.0.1:8000" }
    }
  }
}
```

**Path two, an OpenAPI schema.** ChatGPT's consumer product integrates through Custom GPT Actions rather than MCP, which means it wants a schema, not a server:

```bash
uv run scripts/export_openapi.py --out openapi.json --server https://verity.example.com
```

The schema is generated from the app's own routes, so it cannot describe an endpoint that does not exist. The one thing it cannot infer is the URL an Action will call — that has to be reachable from ChatGPT, which localhost is not — so pass `--server`, or set `VERITY_PUBLIC_URL`. The operation a Custom GPT calls is `audit_document`. Nothing in this repo hosts that URL for you or puts authentication in front of it; deployment is yours.

**What was actually tested, and what was not.** The MCP server starts over stdio, completes the protocol handshake and advertises `audit_document` with a valid input schema; a tool call round-trips through a live `uvicorn` to a live Postgres and comes back with the verdict, the findings and the quoted policy text. The exported schema validates against the OpenAPI specification (3.1.0). Both are covered by `tests/test_integrations.py`, which drives the reference MCP client from the SDK in-process.

That is a check against the standards, not against the products. **This has never been run inside a Claude, Gemini CLI, Cursor, Codex or ChatGPT session.** The claim being made is that the server is MCP-standard and the schema is OpenAPI-valid, so a client that implements either should be able to call it — not that any of those five have been observed doing so. If you are the first to point one at it, expect the usual first-connection friction, and file what you hit.

Optional extras, both off by default and neither on the decision path:

```bash
uv sync --extra obs      # ship traces to Langfuse
uv sync --extra ragas    # optional RAGAS scoring; the retrieval numbers above need neither
```

`ANTHROPIC_API_KEY` enables the citation check (`verity.llm.citation_check`). It runs as a graph
node after `evaluate`, reads the findings, and writes a note. It cannot mutate them — `tests/test_graph.py`
asserts the verdict and finding set are byte-identical with the node on and off. The prompt is a
versioned file (`src/verity/llm/prompts/citation_check.v1.md`) carrying its own model and limits, so
"we changed the wording and the numbers moved" is a diff rather than an argument. Every call comes
back priced through `verity.obs.cost`, which is what makes a per-document and per-batch dollar figure
addition rather than estimation.

Two ways to run one document:

```bash
uv run python -c "from verity.agent.loop import run_audit; print(run_audit('inbox/a.png').verdict)"
```

`verity.agent.graph.run_audit_graph` is the same audit as a LangGraph state machine over the same
tools and the same rules. It returns the identical verdict — there is a parity test per branch — and
additionally reports which nodes it visited, which is what `trajectory_eval` scores. The routing is
deterministic: no branch in that graph consults a model. `run_audit` stays the default for the API
and the batch script, which do not need the route as data.

Running the evaluations:

```bash
uv run -m verity.eval.policy_eval                                    # 14 controls, 19 hand-written cases
uv run -m verity.eval.fraud_eval --corpus sample/verity_sample_invoices_m_500.csv   # held-out fraud set
uv run -m verity.eval.trajectory_eval                                # did the agent take the right route
uv run -m verity.eval.rag_eval --corpus sample/verity_sample_invoices_m_500.csv     # policy search quality
uv run -m verity.eval.extraction_eval --limit 25                     # reading accuracy against CORD/SROIE
```

Those four are deterministic, need no key and no GPU, and run in CI. The two that cost money or
inference time do not:

```bash
# the whole system end to end: renders each labelled row as a page, reads it back
uv run -m verity.eval.fraud_eval --source images --limit 25 --corpus sample/verity_sample_invoices_m_500.csv

# calibration needs a model's own confidence, so it only accepts an --source images report
uv run -m verity.eval.trajectory_eval --calibration fraud_eval_report_images.json

# RAGAS faithfulness and context precision (needs the ragas extra and a key).
# Never run to date -- no README number comes from this path.
uv run -m verity.eval.rag_eval --ragas --limit 25
```

What each number is and is not, since they are easy to quote wrongly:

| Eval | Answers | Does not answer |
|---|---|---|
| `policy_eval` | does each control fire in isolation | whether it catches real fraud (we wrote the cases) |
| `fraud_eval --source fields` | do the controls catch planted fraud, given correct fields | whether the fields were read correctly |
| `fraud_eval --source images` | does the whole system catch planted fraud, reading included | how it fares on real scans (rendered pages are cleaner) |
| `trajectory_eval` | did the router visit the right nodes | whether the tools returned good answers |
| `rag_eval` (`--queries notes`) | can a reviewer find the right policy in their own words | anything about enforcement — search never decides |
| `extraction_eval` | reading accuracy on a public benchmark | reading accuracy on your suppliers' invoices |

`fraud_cases.py` documents every judgement call made building the fraud set, including the two kinds
of counterparty document the source CSVs label but do not contain, which are synthesised there and
nowhere else. Read that module before quoting any number from `fraud_eval`.

Tests and lint:

```bash
uv run pytest
uv run ruff check src tests scripts
```

Both run on every push and pull request (`.github/workflows/ci.yml`), along with the four
deterministic evaluations, whose JSON reports are kept as build artifacts.
