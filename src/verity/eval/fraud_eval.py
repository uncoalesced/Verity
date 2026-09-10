"""Precision and recall against the held-out fraud set.

This is the number the project actually rests on. `policy_eval` scores the
controls against nineteen cases hand-written alongside the controls themselves;
this scores them against a corpus of invoices with injected fraud, labelled
independently of the rules, with the full ledger visible so the cross-document
controls have somewhere real to go wrong.

Four things come out, and they answer different questions:

  per-control precision/recall   when this control fires, should it have, and
                                 does it fire when it should
  detection rate                 of the documents carrying fraud a control
                                 exists for, how many got caught
  coverage gap                   injected fraud types no control covers at all
  noise                          how much of the queue is findings on clean
                                 documents -- a control set nobody can work
                                 through is a control set nobody uses

Only the controls a fraud type maps to are scored (see
`fraud_cases.SCORED_RULES`). P-009 is deliberately excluded: this corpus is
large invoices against a 50,000 approval limit, so P-009 fires on most of them
by design, and folding that into a precision number would say something about
the fixture rather than about the system. Its firing volume is reported under
noise instead of being hidden.

Two ways to run it:

  uv run -m verity.eval.fraud_eval
      Scores the controls on fields taken straight from the CSV. Fast,
      deterministic, no models. Extraction is out of the loop on purpose --
      a missed duplicate and a misread total are different failures and should
      not share a number.

  uv run -m verity.eval.fraud_eval --source images --limit 25
      Renders each row as an invoice image and puts it through the real
      pipeline: triage, Donut extraction, controls. Slower by orders of
      magnitude, and the number that comes out is the whole system end to end,
      reading included -- extraction errors turn into findings here, which is
      the point.

      As of the last run this scores far worse than the fields path (micro
      precision 0.05 over 25 documents, every clean document flagged), and the
      gap between the two numbers *is* the measurement: the controls are fine,
      the reading is the bottleneck. Do not quote the fields number as the
      system's accuracy.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from verity.eval.fraud_cases import (
    DEFAULT_CORPUS,
    SCORED_RULES,
    UNCOVERED_FRAUD_TYPES,
    FraudCase,
    build_cases,
)
from verity.eval.policy_eval import Counts, prf
from verity.policy.rules import AuditContext, evaluate, verdict


@dataclass
class CaseOutcome:
    name: str
    fraud_type: str
    is_fraudulent: bool
    expected: list
    fired: list
    missed: list
    spurious: list
    verdict: str
    caught: bool
    confidence: float


@dataclass
class Report:
    corpus: str = ""
    source: str = "fields"
    cases: int = 0
    fraudulent: int = 0
    per_rule: dict = field(default_factory=dict)
    micro: dict = field(default_factory=dict)
    detection: dict = field(default_factory=dict)
    coverage_gap: dict = field(default_factory=dict)
    noise: dict = field(default_factory=dict)
    outcomes: list = field(default_factory=list)


def run_case(case: FraudCase) -> tuple[set[str], str]:
    """Score one case on the fields as labelled -- no extraction in the loop."""
    ctx = AuditContext(
        fields=case.fields,
        config=case.config,
        document_id=case.document_id,
        filename=case.name,
        history=case.history,
        today=case.today,
    )
    findings = evaluate(ctx)
    return {f.rule_id for f in findings}, verdict(findings)


def score(cases: list[FraudCase], results: list[tuple[set[str], str]], *, corpus: str, source: str) -> Report:
    """Turn per-case outcomes into the four numbers above.

    Split out from the running so the same scoring covers both the fast path and
    the end-to-end image path -- one definition of "caught", whichever way the
    fields were read.
    """
    report = Report(corpus=corpus, source=source, cases=len(cases))
    counts: dict[str, Counts] = {rule_id: Counts() for rule_id in sorted(SCORED_RULES)}

    all_fired: Counter[str] = Counter()
    clean_with_scored_finding = 0
    clean_with_any_finding = 0
    clean_total = 0
    caught = 0
    covered_fraud = 0
    uncovered_seen: Counter[str] = Counter()
    uncovered_flagged: Counter[str] = Counter()

    for case, (fired, case_verdict) in zip(cases, results):
        expected = set(case.expected)
        scored_fired = fired & SCORED_RULES
        all_fired.update(fired)

        for rule_id in scored_fired & expected:
            counts[rule_id].tp += 1
        for rule_id in scored_fired - expected:
            counts[rule_id].fp += 1
        for rule_id in expected - scored_fired:
            counts[rule_id].fn += 1

        is_caught = bool(expected) and expected <= fired
        if expected:
            covered_fraud += 1
            caught += int(is_caught)

        if case.uncovered_reason:
            uncovered_seen[case.fraud_type] += 1
            if fired:
                uncovered_flagged[case.fraud_type] += 1

        if not case.is_fraudulent:
            clean_total += 1
            clean_with_scored_finding += int(bool(scored_fired))
            clean_with_any_finding += int(bool(fired))

        report.fraudulent += int(case.is_fraudulent)
        report.outcomes.append(
            CaseOutcome(
                name=case.name,
                fraud_type=case.fraud_type,
                is_fraudulent=case.is_fraudulent,
                expected=sorted(expected),
                fired=sorted(fired),
                missed=sorted(expected - fired),
                spurious=sorted(scored_fired - expected),
                verdict=case_verdict,
                caught=is_caught,
                confidence=round(case.fields.confidence, 4),
            )
        )

    micro = Counts()
    for c in counts.values():
        micro.tp += c.tp
        micro.fp += c.fp
        micro.fn += c.fn

    report.per_rule = {rule_id: prf(c) for rule_id, c in counts.items()}
    report.micro = prf(micro)
    report.detection = {
        "documents_with_covered_fraud": covered_fraud,
        "caught": caught,
        "detection_rate": round(caught / covered_fraud, 4) if covered_fraud else 0.0,
    }
    report.coverage_gap = {
        fraud_type: {
            "documents": uncovered_seen[fraud_type],
            "reason": reason,
            # Flagged for some *other* reason. Not detection -- a document can
            # trip the approval limit while its actual fraud goes unseen.
            "flagged_incidentally": uncovered_flagged[fraud_type],
        }
        for fraud_type, reason in UNCOVERED_FRAUD_TYPES.items()
        if uncovered_seen[fraud_type]
    }
    report.noise = {
        "clean_documents": clean_total,
        "clean_with_scored_finding": clean_with_scored_finding,
        "clean_with_any_finding": clean_with_any_finding,
        "false_positive_rate_scored": (
            round(clean_with_scored_finding / clean_total, 4) if clean_total else 0.0
        ),
        "any_finding_rate": round(clean_with_any_finding / clean_total, 4) if clean_total else 0.0,
        "firing_volume": dict(sorted(all_fired.items())),
    }
    return report


def evaluate_fields(cases: list[FraudCase], corpus: str) -> Report:
    return score(cases, [run_case(c) for c in cases], corpus=corpus, source="fields")


def evaluate_images(cases: list[FraudCase], corpus: str, out_dir: Path) -> Report:
    """The end-to-end path: render each case, then audit the rendered page.

    Imported lazily -- rendering pulls PIL's font machinery and the audit pulls
    torch, and neither should load for the fast path or for `--help`.
    """
    from verity.agent.loop import run_audit
    from verity.agent.tools import default_toolbox, history_from_documents
    from verity.eval.render import render_case

    results: list[tuple[set[str], str]] = []
    for case in cases:
        path = render_case(case, out_dir)
        result = run_audit(
            path,
            toolbox=default_toolbox(
                history=history_from_documents(case.history),
                # A rendered page carries no signature by construction, so the
                # detector would correctly report one missing on every document
                # and P-008 would be measuring the renderer rather than the
                # corpus. Same reasoning as `signature_present=None` on the
                # fields path: not checked beats inventing an absence.
                signature_detection_enabled=False,
            ),
            config=case.config,
            document_id=case.document_id,
            today=case.today,
        )
        # The reading is now the model's, not the label's. Keep it on the case so
        # the confidence reported beside each outcome is the confidence that
        # actually drove P-013.
        case.fields = result.fields
        results.append(({f.rule_id for f in result.findings}, result.verdict))
    return score(cases, results, corpus=corpus, source="images")


def print_report(report: Report) -> None:
    print(f"\n{report.cases} document(s) from {Path(report.corpus).name}, read from {report.source}")
    print(f"{report.fraudulent} carry injected fraud\n")

    print(f"{'control':<10}{'precision':>10}{'recall':>10}{'f1':>8}{'support':>9}")
    print("-" * 47)
    for rule_id, s in sorted(report.per_rule.items()):
        print(f"{rule_id:<10}{s['precision']:>10.3f}{s['recall']:>10.3f}{s['f1']:>8.3f}{s['support']:>9}")
    m = report.micro
    print("-" * 47)
    print(f"{'MICRO':<10}{m['precision']:>10.3f}{m['recall']:>10.3f}{m['f1']:>8.3f}{m['support']:>9}")

    d = report.detection
    print(
        f"\ncaught {d['caught']}/{d['documents_with_covered_fraud']} documents carrying fraud a "
        f"control covers ({d['detection_rate']:.0%})"
    )

    if report.coverage_gap:
        print("\ninjected fraud with no control:")
        for fraud_type, info in sorted(report.coverage_gap.items()):
            print(
                f"  {fraud_type:<22}{info['documents']:>4} document(s) -- {info['reason']}"
                f" ({info['flagged_incidentally']} flagged for other reasons)"
            )

    n = report.noise
    print(
        f"\n{n['clean_with_scored_finding']}/{n['clean_documents']} clean documents trip a scored "
        f"control ({n['false_positive_rate_scored']:.0%}); "
        f"{n['any_finding_rate']:.0%} trip some control, routing included"
    )
    print("firing volume: " + ", ".join(f"{k}={v}" for k, v in n["firing_volume"].items()))

    misses = [o for o in report.outcomes if o.missed]
    if misses:
        print("\nmissed:")
        for o in misses:
            fired = ", ".join(o.fired) or "nothing"
            print(f"  {o.name} ({o.fraud_type}): expected {', '.join(o.missed)}, fired {fired}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Precision/recall against the held-out fraud set")
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS), help="labelled invoice CSV")
    ap.add_argument("--source", choices=("fields", "images"), default="fields")
    ap.add_argument("--limit", type=int, default=0, help="score only the first N documents")
    ap.add_argument("--render-dir", default="", help="where --source images writes rendered pages")
    ap.add_argument("--out", default="fraud_eval_report.json")
    args = ap.parse_args()

    cases = build_cases(path=args.corpus)
    if args.limit:
        cases = cases[: args.limit]

    if args.source == "images":
        out_dir = Path(args.render_dir or "rendered_invoices")
        report = evaluate_images(cases, args.corpus, out_dir)
    else:
        report = evaluate_fields(cases, args.corpus)

    print_report(report)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(asdict(report), fh, indent=2)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
