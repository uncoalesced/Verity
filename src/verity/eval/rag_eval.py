"""How good is the policy search, and do the findings stay faithful to it?

`policy/retrieval.py` is TF-IDF over fourteen short policies, and it is
deliberately outside the enforcement path -- every control runs regardless of
what search returns. But it is what answers a reviewer's question in their own
words ("which controls cover unsigned invoices?"), so its quality is worth a
number rather than a shrug.

Two layers, because they need different things to run:

**Retrieval hit rate** needs nothing but the library: does the policy a control
cited come back in the top k for a question about that problem? Reported as
hit@1, hit@3 and mean reciprocal rank. It runs in CI, costs nothing, and is the
number that moves if someone changes the tokeniser or the term weighting.

Where the question comes from decides whether that number means anything, so
there are two sources and the default is the harder one:

* `--queries notes` (default) uses the corpus's own `notes` column -- an
  independent description of the problem written by whoever generated the
  labels ("Total does not reconcile with subtotal + tax"). Different words from
  the policy, different words from the finding. This is the honest measurement.
* `--queries finding` uses the finding's own message. It scores near-perfectly
  and that result is close to meaningless: the finding text is generated from
  the policy's own vocabulary, so the query and the target share their wording
  by construction. Kept because it is a useful regression canary -- if *this*
  ever drops, something is badly wrong -- not because it is evidence.

**RAGAS faithfulness and context precision** need Claude and the `ragas` extra.
Faithfulness asks whether the finding's claim is supported by the policy text
retrieval returned; context precision asks whether the retrieved passages are
the relevant ones, scored against the cited policy as reference. These are the
metrics the spec names, run through the real library rather than reimplemented.

    uv sync --extra ragas
    ANTHROPIC_API_KEY=... uv run -m verity.eval.rag_eval --ragas --limit 25

A weak RAGAS score here is a legitimate result, not a reason to swap TF-IDF for
embeddings on the spot. Retrieval quality and generation faithfulness are
different failures with different fixes, and the hit rate above tells you which
one you are looking at.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from verity.eval.fraud_cases import DEFAULT_CORPUS, build_cases
from verity.llm.client import DEFAULT_MODEL, available
from verity.policy.retrieval import default_index
from verity.policy.rules import AuditContext, evaluate

# How many policies a reviewer is shown. Hit@k is reported at 1 and at this.
TOP_K = 3


@dataclass
class Sample:
    """One retrieval question, and what the library gave back.

    `expected_policy_id` is the control that actually fired, so ground truth
    comes from the deterministic engine rather than from a second opinion about
    what should have matched.
    """

    document: str
    query: str
    expected_policy_id: str
    expected_policy_text: str
    retrieved_ids: list[str] = field(default_factory=list)
    retrieved_texts: list[str] = field(default_factory=list)

    @property
    def rank(self) -> int | None:
        """1-based position of the right policy, or None if it never appeared."""
        if self.expected_policy_id in self.retrieved_ids:
            return self.retrieved_ids.index(self.expected_policy_id) + 1
        return None


@dataclass
class RagReport:
    corpus: str = ""
    query_source: str = ""
    queries: int = 0
    top_k: int = TOP_K
    retrieval: dict = field(default_factory=dict)
    ragas: dict = field(default_factory=dict)
    samples: list = field(default_factory=list)


NOTES = "notes"
FINDING = "finding"
QUERY_SOURCES = (NOTES, FINDING)


def build_samples(cases, top_k: int = TOP_K, queries: str = NOTES) -> list[Sample]:
    """One sample per finding, asked the way `queries` says to ask it.

    With `queries="notes"`, only documents carrying an independent description
    of the problem produce samples, and only for the control that owns that
    problem -- pairing a note about a duplicate with a finding about the
    approval limit would score retrieval against the wrong target.
    """
    if queries not in QUERY_SOURCES:
        raise ValueError(f"queries must be one of {QUERY_SOURCES}, got {queries!r}")

    index = default_index()
    samples: list[Sample] = []

    for case in cases:
        ctx = AuditContext(
            fields=case.fields,
            config=case.config,
            document_id=case.document_id,
            filename=case.name,
            history=case.history,
            today=case.today,
        )
        for finding in evaluate(ctx):
            if not finding.policy_text:
                continue
            if queries == NOTES:
                # The note describes one problem. Score it only against the
                # control whose job that problem is.
                if not case.note or finding.rule_id not in case.expected:
                    continue
                question = case.note
            else:
                question = finding.message

            hits = index.search(question, k=top_k)
            samples.append(
                Sample(
                    document=case.name,
                    query=question,
                    expected_policy_id=finding.rule_id,
                    expected_policy_text=finding.policy_text,
                    retrieved_ids=[h.policy.id for h in hits],
                    retrieved_texts=[h.policy.text for h in hits],
                )
            )
    return samples


def retrieval_hits(samples: list[Sample], top_k: int = TOP_K) -> dict:
    """Hit@1, hit@k and MRR over the cited policy."""
    if not samples:
        return {
            "queries": 0,
            "hit_at_1": 0.0,
            f"hit_at_{top_k}": 0.0,
            "mrr": 0.0,
            "never_retrieved": [],
        }

    ranks = [s.rank for s in samples]
    hit_1 = sum(1 for r in ranks if r == 1)
    hit_k = sum(1 for r in ranks if r is not None)
    mrr = sum(1 / r for r in ranks if r is not None) / len(samples)
    return {
        "queries": len(samples),
        "hit_at_1": round(hit_1 / len(samples), 4),
        f"hit_at_{top_k}": round(hit_k / len(samples), 4),
        "mrr": round(mrr, 4),
        # Controls whose own policy never came back for a question about the
        # problem they exist to catch. A reviewer searching for that problem in
        # their own words would not find the control that covers it.
        "never_retrieved": sorted({s.expected_policy_id for s in samples if s.rank is None}),
    }


def evaluate_ragas(samples: list[Sample], model: str | None = None) -> dict:
    """Faithfulness and context precision, through the real ragas library.

    Raises rather than returning zeros when it cannot run. A RAG score of 0.0
    and "we could not measure it" are opposite findings and must not share a
    representation.
    """
    if not available():
        raise RuntimeError("RAGAS scoring needs ANTHROPIC_API_KEY; nothing was measured")

    import asyncio

    import anthropic
    from ragas.llms import llm_factory
    from ragas.metrics.collections import ContextPrecisionWithReference, Faithfulness

    chosen = model or DEFAULT_MODEL
    llm = llm_factory(chosen, provider="anthropic", client=anthropic.Anthropic())
    faithfulness = Faithfulness(llm=llm)
    precision = ContextPrecisionWithReference(llm=llm)

    async def score_all() -> tuple[list[float], list[float]]:
        faith_scores, precision_scores = [], []
        for sample in samples:
            faith = await faithfulness.ascore(
                user_input=sample.query,
                response=sample.query,
                retrieved_contexts=sample.retrieved_texts,
            )
            prec = await precision.ascore(
                user_input=sample.query,
                reference=sample.expected_policy_text,
                retrieved_contexts=sample.retrieved_texts,
            )
            faith_scores.append(float(faith.value))
            precision_scores.append(float(prec.value))
        return faith_scores, precision_scores

    faith_scores, precision_scores = asyncio.run(score_all())

    def mean(scores: list[float]) -> float:
        return round(sum(scores) / len(scores), 4) if scores else 0.0

    return {
        "model": chosen,
        "samples": len(samples),
        "faithfulness": mean(faith_scores),
        "context_precision": mean(precision_scores),
    }


def print_report(report: RagReport) -> None:
    r = report.retrieval
    print(f"\n{report.queries} retrieval question(s) from {Path(report.corpus).name}\n")
    print(f"  hit@1                {r['hit_at_1']:.3f}")
    print(f"  hit@{report.top_k}                {r[f'hit_at_{report.top_k}']:.3f}")
    print(f"  mean reciprocal rank {r['mrr']:.3f}")
    if r["never_retrieved"]:
        print(f"\n  never retrieved for their own finding text: {', '.join(r['never_retrieved'])}")

    if report.ragas:
        g = report.ragas
        print(f"\nRAGAS ({g['model']}, {g['samples']} sample(s))")
        print(f"  faithfulness      {g['faithfulness']:.3f}")
        print(f"  context precision {g['context_precision']:.3f}")
    else:
        print("\nRAGAS not run (pass --ragas, with the ragas extra and an API key)")


def main() -> None:
    ap = argparse.ArgumentParser(description="Policy retrieval quality, with optional RAGAS scoring")
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    ap.add_argument("--limit", type=int, default=0, help="score only the first N documents")
    ap.add_argument("--top-k", type=int, default=TOP_K)
    ap.add_argument(
        "--queries",
        choices=QUERY_SOURCES,
        default=NOTES,
        help="notes: independent problem descriptions (the honest measurement). "
        "finding: the finding's own words, which share the policy's vocabulary",
    )
    ap.add_argument("--ragas", action="store_true", help="also run RAGAS (needs a key and the extra)")
    ap.add_argument("--model", default="", help="override the model RAGAS judges with")
    ap.add_argument("--out", default="rag_eval_report.json")
    args = ap.parse_args()

    cases = build_cases(path=args.corpus)
    if args.limit:
        cases = cases[: args.limit]

    samples = build_samples(cases, top_k=args.top_k, queries=args.queries)
    report = RagReport(
        corpus=args.corpus,
        query_source=args.queries,
        queries=len(samples),
        top_k=args.top_k,
        retrieval=retrieval_hits(samples, top_k=args.top_k),
        samples=[asdict(s) for s in samples],
    )
    if args.ragas:
        report.ragas = evaluate_ragas(samples, model=args.model or None)

    print_report(report)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(asdict(report), fh, indent=2)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
