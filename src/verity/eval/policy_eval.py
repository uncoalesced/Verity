"""Control-level precision and recall.

For each labelled case, run every control and compare the set of controls that
fired against the set that should have. Three numbers come out per control:

  precision  when this control fires, how often it should have
  recall     when this control should fire, how often it does
  f1         the two combined

A control with perfect recall and poor precision is a control that cries wolf,
and a queue full of wolves gets ignored. Both numbers are reported for every
control rather than rolled into one score, because the remedy differs.

Run it with:  uv run -m verity.eval.policy_eval
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field

from verity.eval.cases import CASES, TODAY, Case
from verity.policy.library import POLICIES
from verity.policy.rules import AuditContext, evaluate, verdict


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0


def prf(counts: Counts) -> dict:
    precision = counts.tp / (counts.tp + counts.fp) if counts.tp + counts.fp else 0.0
    recall = counts.tp / (counts.tp + counts.fn) if counts.tp + counts.fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "support": counts.tp + counts.fn,
        **asdict(counts),
    }


@dataclass
class CaseOutcome:
    name: str
    expected: list
    fired: list
    missed: list
    spurious: list
    verdict: str
    exact: bool
    note: str = ""


@dataclass
class Report:
    cases: int = 0
    exact_matches: int = 0
    per_rule: dict = field(default_factory=dict)
    micro: dict = field(default_factory=dict)
    outcomes: list = field(default_factory=list)

    @property
    def exact_match_rate(self) -> float:
        return self.exact_matches / self.cases if self.cases else 0.0


def run_case(case: Case) -> tuple[set[str], str]:
    """Evaluate one case, returning the controls that fired and the verdict."""
    ctx = AuditContext(
        fields=case.fields,
        config=case.config,
        filename=case.name,
        ingestion_status=case.ingestion_status,
        reject_reason=case.reject_reason,
        history=case.history,
        today=TODAY,
    )
    findings = evaluate(ctx)
    return {f.rule_id for f in findings}, verdict(findings)


def evaluate_cases(cases: tuple[Case, ...] = CASES) -> Report:
    counts: dict[str, Counts] = {p.id: Counts() for p in POLICIES}
    report = Report()

    for case in cases:
        fired, case_verdict = run_case(case)
        expected = set(case.expected)

        for rule_id in fired & expected:
            counts[rule_id].tp += 1
        for rule_id in fired - expected:
            counts[rule_id].fp += 1
        for rule_id in expected - fired:
            counts[rule_id].fn += 1

        report.cases += 1
        exact = fired == expected
        report.exact_matches += int(exact)
        report.outcomes.append(
            CaseOutcome(
                name=case.name,
                expected=sorted(expected),
                fired=sorted(fired),
                missed=sorted(expected - fired),
                spurious=sorted(fired - expected),
                verdict=case_verdict,
                exact=exact,
                note=case.note,
            )
        )

    micro = Counts()
    for c in counts.values():
        micro.tp += c.tp
        micro.fp += c.fp
        micro.fn += c.fn

    # Controls with no labelled case are reported as untested rather than as
    # perfect. A control nobody has written a case for is a control nobody has
    # checked.
    report.per_rule = {
        rule_id: prf(c) for rule_id, c in counts.items() if c.tp or c.fp or c.fn
    }
    report.micro = prf(micro)
    return report


def untested_rules(report: Report) -> list[str]:
    return sorted(p.id for p in POLICIES if p.id not in report.per_rule)


def print_report(report: Report) -> None:
    print(f"\n{report.cases} labelled case(s)\n")
    print(f"{'control':<10}{'precision':>10}{'recall':>10}{'f1':>8}{'support':>9}")
    print("-" * 47)
    for rule_id, s in sorted(report.per_rule.items()):
        print(f"{rule_id:<10}{s['precision']:>10.3f}{s['recall']:>10.3f}{s['f1']:>8.3f}{s['support']:>9}")
    m = report.micro
    print("-" * 47)
    print(f"{'MICRO':<10}{m['precision']:>10.3f}{m['recall']:>10.3f}{m['f1']:>8.3f}{m['support']:>9}")
    print(f"\nexact match on {report.exact_matches}/{report.cases} cases "
          f"({report.exact_match_rate:.0%})")

    wrong = [o for o in report.outcomes if not o.exact]
    if wrong:
        print("\ncases where the control set did not match")
        for o in wrong:
            if o.missed:
                print(f"  {o.name}: missed {', '.join(o.missed)}")
            if o.spurious:
                print(f"  {o.name}: also fired {', '.join(o.spurious)}")

    untested = untested_rules(report)
    if untested:
        print(f"\nuntested (no labelled case): {', '.join(untested)}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Control-level precision/recall")
    ap.add_argument("--out", default="policy_eval_report.json")
    args = ap.parse_args()

    report = evaluate_cases()
    print_report(report)

    payload = asdict(report)
    payload["exact_match_rate"] = round(report.exact_match_rate, 4)
    payload["untested_rules"] = untested_rules(report)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
