"""Did the agent take the right route, and does it know when it is unsure?

Two metrics that only became measurable once the audit became a graph
(`verity.agent.graph`), because a straight-line function has no route to get
wrong.

**Trajectory success rate.** Given what the tools returned, did the router make
the right choices -- skip extraction on a document intake rejected, stop before
extraction when no page image could be produced, skip signature detection when
it is switched off, run the citation node only when it is configured. The
expected route is derived from the document's observable state, not from what
the graph did, which is the whole point: a metric computed from the thing it is
scoring measures nothing.

This deliberately scores *routing*, not tools. A run where extraction returned
nonsense but the router visited the right nodes counts as a trajectory success,
because the trajectory was right; the reading is what `extraction_eval` is for.
Keeping them apart is what makes either number actionable.

**Calibration.** Extraction reports a confidence, and P-013 routes documents to
a human below a threshold. That threshold is only worth anything if the
confidence tracks correctness -- if documents read at 0.95 are right more often
than documents read at 0.65. Calibration buckets the fraud-eval outcomes by
confidence and reports how often each bucket was actually right, plus the gap
between the two (expected calibration error).

Calibration needs a *model's* confidence to mean anything, so it only accepts a
report produced with `--source images`. The fields path takes confidence from a
CSV column, where it is a label rather than a reading, and bucketing labels
against correctness would produce a curve that looks like calibration and is not.

Run it with:
  uv run -m verity.eval.trajectory_eval
  uv run -m verity.eval.trajectory_eval --calibration fraud_eval_report_images.json
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from verity.agent import graph
from verity.agent.tools import PageLoadError, Toolbox

# --- what the right route looks like ---------------------------------------


def expected_route(
    *,
    intake_accepted: bool,
    page_loaded: bool,
    signature_enabled: bool,
    check_citations: bool = False,
) -> list[str]:
    """The nodes a document of this shape must visit, in order.

    Written from the policy, not from the graph: intake rejection short-circuits
    to the controls because nothing was read, an unloadable page does the same
    one step later, and the two optional steps appear only when switched on.
    """
    if not intake_accepted:
        route = [graph.TRIAGE, graph.EVALUATE]
    elif not page_loaded:
        route = [graph.TRIAGE, graph.LOAD_IMAGE, graph.EVALUATE]
    else:
        route = [graph.TRIAGE, graph.LOAD_IMAGE, graph.READ_FIELDS]
        if signature_enabled:
            route.append(graph.DETECT_SIGNATURE)
        route += [graph.HISTORY, graph.EVALUATE]
    if check_citations:
        route.append(graph.CHECK_CITATIONS)
    return route


@dataclass
class Scenario:
    """One document shape, and the route it ought to produce."""

    name: str
    path: Path
    toolbox: Toolbox
    expected: list[str]
    check_citations: bool = False
    note: str = ""


@dataclass
class TrajectoryOutcome:
    name: str
    expected: list
    visited: list
    ok: bool
    note: str = ""


@dataclass
class TrajectoryReport:
    scenarios: int = 0
    successes: int = 0
    outcomes: list = field(default_factory=list)
    calibration: dict = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        return self.successes / self.scenarios if self.scenarios else 0.0


def evaluate_trajectories(scenarios: list[Scenario]) -> TrajectoryReport:
    """Run every scenario through the graph and compare route to expectation."""
    report = TrajectoryReport(scenarios=len(scenarios))
    for scenario in scenarios:
        result = graph.run_audit_graph(
            scenario.path,
            toolbox=scenario.toolbox,
            check_citations=scenario.check_citations,
        )
        ok = result.visited == scenario.expected
        report.successes += int(ok)
        report.outcomes.append(
            TrajectoryOutcome(
                name=scenario.name,
                expected=list(scenario.expected),
                visited=list(result.visited),
                ok=ok,
                note=scenario.note,
            )
        )
    return report


# --- the scenarios ---------------------------------------------------------


def _write_pages(out_dir: Path) -> tuple[Path, Path]:
    """An inked page intake accepts, and a blank one it rejects."""
    from PIL import Image

    out_dir.mkdir(parents=True, exist_ok=True)
    inked = out_dir / "readable.png"
    image = Image.new("RGB", (160, 160), "white")
    for x in range(20, 140):
        for y in range(50, 90):
            image.putpixel((x, y), (0, 0, 0))
    image.save(inked)

    blank = out_dir / "blank.png"
    Image.new("RGB", (160, 160), "white").save(blank)
    return inked, blank


def default_scenarios(out_dir: Path) -> list[Scenario]:
    """The routes worth checking, one per branch the router can take."""
    from PIL import Image

    from verity.extraction.schema import ExtractedFields

    inked, blank = _write_pages(out_dir)

    def toolbox(**overrides) -> Toolbox:
        base = {
            "load_image": lambda path: Image.open(path).convert("RGB"),
            "read_fields": lambda image, dayfirst=False: ExtractedFields(confidence=0.9),
            "read_field": lambda image, field_name, question=None: "",
            "detect_signature": lambda image: (True, 0.9),
            "history": lambda fields: [],
        }
        base.update(overrides)
        return Toolbox(**base)

    def unloadable(path):
        raise PageLoadError("born-digital PDF carries no embedded page image")

    return [
        Scenario(
            name="readable page, everything on",
            path=inked,
            toolbox=toolbox(),
            expected=expected_route(intake_accepted=True, page_loaded=True, signature_enabled=True),
            note="the full route",
        ),
        Scenario(
            name="signature detection switched off",
            path=inked,
            toolbox=toolbox(signature_detection_enabled=False),
            expected=expected_route(intake_accepted=True, page_loaded=True, signature_enabled=False),
            note="the optional step must be skipped, not run and ignored",
        ),
        Scenario(
            name="intake rejects a blank page",
            path=blank,
            toolbox=toolbox(),
            expected=expected_route(intake_accepted=False, page_loaded=False, signature_enabled=True),
            note="nothing was read, so nothing downstream may comment",
        ),
        Scenario(
            name="page cannot be turned into an image",
            path=inked,
            toolbox=toolbox(load_image=unloadable),
            expected=expected_route(intake_accepted=True, page_loaded=False, signature_enabled=True),
            note="stops one step later than a rejected intake, same outcome",
        ),
        Scenario(
            name="citation check requested",
            path=inked,
            toolbox=toolbox(),
            check_citations=True,
            expected=expected_route(
                intake_accepted=True, page_loaded=True, signature_enabled=True, check_citations=True
            ),
            note="the model step runs last, after the controls have decided",
        ),
    ]


# --- calibration -----------------------------------------------------------


@dataclass
class Bucket:
    lower: float
    upper: float
    documents: int = 0
    correct: int = 0
    confidence_sum: float = 0.0

    @property
    def accuracy(self) -> float:
        return self.correct / self.documents if self.documents else 0.0

    @property
    def mean_confidence(self) -> float:
        return self.confidence_sum / self.documents if self.documents else 0.0

    def as_dict(self) -> dict:
        return {
            "range": [round(self.lower, 2), round(self.upper, 2)],
            "documents": self.documents,
            "correct": self.correct,
            "accuracy": round(self.accuracy, 4),
            "mean_confidence": round(self.mean_confidence, 4),
            "gap": round(self.mean_confidence - self.accuracy, 4),
        }


def calibrate(outcomes: list[dict], bins: int = 5) -> dict:
    """Bucket documents by reading confidence and compare it to being right.

    "Right" is the exact control set: nothing missed and nothing spurious. A
    document where the controls half-agreed is not half-right -- an approver
    acting on it would act on the wrong finding.
    """
    edges = [(i / bins, (i + 1) / bins) for i in range(bins)]
    buckets = [Bucket(lower=lo, upper=hi) for lo, hi in edges]

    for outcome in outcomes:
        confidence = float(outcome.get("confidence", 0.0))
        index = min(int(confidence * bins), bins - 1)
        bucket = buckets[index]
        bucket.documents += 1
        bucket.confidence_sum += confidence
        bucket.correct += int(not outcome.get("missed") and not outcome.get("spurious"))

    scored = sum(b.documents for b in buckets)
    # Expected calibration error: how far, on average, stated confidence sits
    # from measured correctness. Near zero means the number can be read as a
    # probability; a large positive value means the reader is overconfident.
    ece = (
        sum(b.documents * abs(b.mean_confidence - b.accuracy) for b in buckets) / scored
        if scored
        else 0.0
    )
    return {
        "documents": scored,
        "expected_calibration_error": round(ece, 4),
        "buckets": [b.as_dict() for b in buckets if b.documents],
    }


def calibration_from_report(path: str | Path) -> dict:
    """Read a fraud-eval report and calibrate from its outcomes.

    Refuses a report produced from CSV fields: that confidence column is a
    label, not a model's own reading, and bucketing it would draw a calibration
    curve for something that never made a prediction.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("source") != "images":
        raise ValueError(
            f"{path} was scored from '{payload.get('source')}'. Calibration needs a model's own "
            "confidence -- rerun the fraud eval with --source images."
        )
    return calibrate(payload.get("outcomes", []))


# --- reporting -------------------------------------------------------------


def print_report(report: TrajectoryReport) -> None:
    print(f"\n{report.scenarios} routing scenario(s)\n")
    for outcome in report.outcomes:
        mark = "ok  " if outcome.ok else "FAIL"
        print(f"  {mark} {outcome.name}")
        if not outcome.ok:
            print(f"       expected {' -> '.join(outcome.expected)}")
            print(f"       visited  {' -> '.join(outcome.visited)}")
    print(f"\ntrajectory success rate {report.successes}/{report.scenarios} ({report.success_rate:.0%})")

    if report.calibration:
        c = report.calibration
        print(f"\ncalibration over {c['documents']} document(s)")
        print(f"{'confidence':<14}{'documents':>10}{'accuracy':>10}{'mean conf':>11}{'gap':>8}")
        print("-" * 53)
        for bucket in c["buckets"]:
            lo, hi = bucket["range"]
            print(
                f"{f'{lo:.1f}-{hi:.1f}':<14}{bucket['documents']:>10}{bucket['accuracy']:>10.3f}"
                f"{bucket['mean_confidence']:>11.3f}{bucket['gap']:>8.3f}"
            )
        print(f"\nexpected calibration error {c['expected_calibration_error']:.3f}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Trajectory success rate and confidence calibration")
    ap.add_argument("--work-dir", default="", help="where the scenario pages are written")
    ap.add_argument(
        "--calibration",
        default="",
        help="a fraud_eval report produced with --source images, to calibrate from",
    )
    ap.add_argument("--out", default="trajectory_eval_report.json")
    args = ap.parse_args()

    work_dir = Path(args.work_dir or "trajectory_pages")
    report = evaluate_trajectories(default_scenarios(work_dir))
    if args.calibration:
        report.calibration = calibration_from_report(args.calibration)

    print_report(report)

    payload = asdict(report)
    payload["success_rate"] = round(report.success_rate, 4)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
