"""Auditing a folder instead of a file.

Month 2 audits one document per call. A finance team does not receive one
document; it receives a month of them. This runs the same loop across a folder
and returns the numbers a controller actually asks for first: how many were
held, how many cleared, which controls did the holding.

Two decisions worth naming:

* One bad document never stops the batch. A file that raises is recorded as a
  failed run and the run continues, because a batch that dies on document 40 of
  200 leaves the other 160 silently unaudited.
* Every document gets its own trace. There is no batch-level summary standing
  in for per-document evidence.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from verity.agent.loop import AuditResult, run_audit
from verity.agent.tools import Toolbox
from verity.policy.library import PolicyConfig
from verity.policy.rules import BLOCKED, PASS, REVIEW

log = logging.getLogger(__name__)

# Extensions the intake router can do something with. Anything else in the
# folder is skipped quietly rather than counted as a rejected document.
DOCUMENT_SUFFIXES = frozenset(
    {".pdf", ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif", ".webp"}
)


@dataclass
class BatchReport:
    """What one pass over a folder produced."""

    directory: str
    results: list[AuditResult] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def documents(self) -> int:
        return len(self.results)

    @property
    def by_verdict(self) -> dict[str, int]:
        counts = Counter(r.verdict for r in self.results)
        return {verdict: counts.get(verdict, 0) for verdict in (PASS, REVIEW, BLOCKED)}

    @property
    def by_rule(self) -> dict[str, int]:
        """How often each control fired, worst offenders first."""
        counts = Counter(f.rule_id for r in self.results for f in r.findings)
        return dict(counts.most_common())

    @property
    def held(self) -> list[AuditResult]:
        """Everything a human has to look at before money moves."""
        return [r for r in self.results if r.verdict in (REVIEW, BLOCKED)]

    def as_dict(self) -> dict:
        return {
            "directory": self.directory,
            "documents": self.documents,
            "by_verdict": self.by_verdict,
            "by_rule": self.by_rule,
            "errors": [{"file": name, "error": message} for name, message in self.errors],
            "runs": [
                {
                    "run_id": r.trace.run_id,
                    "filename": r.filename,
                    "verdict": r.verdict,
                    "rule_ids": [f.rule_id for f in r.findings],
                }
                for r in self.results
            ],
        }


def iter_documents(directory: str | Path, recursive: bool = False) -> Iterator[Path]:
    """Every file in the folder the intake router might accept, in a stable order."""
    directory = Path(directory)
    walker = directory.rglob("*") if recursive else directory.glob("*")
    for path in sorted(walker):
        if path.is_file() and path.suffix.lower() in DOCUMENT_SUFFIXES:
            yield path


def audit_paths(
    paths: Iterable[str | Path],
    *,
    toolbox: Toolbox | None = None,
    config: PolicyConfig | None = None,
    directory: str = "",
    on_result=None,
) -> BatchReport:
    """Audit an explicit list of files.

    `on_result` is called as `on_result(result, path)` for each document as it
    completes, which is how the caller persists rows without this module knowing
    anything about a database. The path is passed because `AuditResult` carries
    only the file name, and a caller writing an intake record needs the location
    it was read from.
    """
    report = BatchReport(directory=directory)
    for path in paths:
        path = Path(path)
        try:
            result = run_audit(path, toolbox=toolbox, config=config)
        except Exception as exc:  # noqa: BLE001 -- see the module docstring
            # Deliberately broad. Any failure on one document is recorded and
            # the batch continues; a batch that dies on document 40 of 200
            # leaves the other 160 silently unaudited.
            log.warning("audit failed for %s: %s", path.name, exc)
            report.errors.append((path.name, f"{type(exc).__name__}: {exc}"))
            continue
        report.results.append(result)
        if on_result is not None:
            on_result(result, path)
    return report


def audit_directory(
    directory: str | Path,
    *,
    toolbox: Toolbox | None = None,
    config: PolicyConfig | None = None,
    recursive: bool = False,
    limit: int | None = None,
    on_result=None,
) -> BatchReport:
    """Run every document in a folder through the audit loop."""
    directory = Path(directory)
    paths = list(iter_documents(directory, recursive=recursive))
    if limit is not None:
        paths = paths[:limit]
    return audit_paths(
        paths,
        toolbox=toolbox,
        config=config,
        directory=str(directory),
        on_result=on_result,
    )


def print_report(report: BatchReport) -> None:
    counts = report.by_verdict
    print(f"\n{report.documents} document(s) from {report.directory}\n")
    print(f"  cleared   {counts[PASS]:>4}")
    print(f"  review    {counts[REVIEW]:>4}")
    print(f"  blocked   {counts[BLOCKED]:>4}")
    if report.errors:
        print(f"  errored   {len(report.errors):>4}")
    if report.by_rule:
        print("\ncontrols that fired")
        for rule_id, count in report.by_rule.items():
            print(f"  {rule_id}  {count}")
