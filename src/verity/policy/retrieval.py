"""Search over the control library.

Retrieval is deliberately *not* in the enforcement path. Every rule in
`rules.py` runs on every document, because a control that silently fails to fire
is worse than no control at all -- a retriever that misses P-002 turns a
duplicate payment into a clean audit. What retrieval does instead is answer
questions in the reviewer's own words ("which controls cover unsigned
invoices?") and pull the policy passage that gets quoted on a finding.

Scoring is TF-IDF cosine over the library. The corpus is fourteen short
documents, so an in-process index is the right size of tool.

ponytail: TF-IDF over an in-memory corpus, rebuilt per process. Move to
embeddings + pgvector when the library outgrows a few hundred policies or when
reviewers need paraphrase matching rather than keyword overlap.
"""

from __future__ import annotations

import functools
import math
import re
from collections import Counter
from dataclasses import dataclass

from verity.policy.library import POLICIES, Policy

_TOKEN = re.compile(r"[a-z0-9]+")

# Words that appear in nearly every policy and carry no discriminating signal.
STOPWORDS = frozenset(
    """a an the and or of to in on for is are be been must not no any all that
    this it its as at by with from than then may can cannot""".split()
)


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in STOPWORDS and len(t) > 1]


def _policy_terms(policy: Policy) -> list[str]:
    """Title and tags are weighted by repetition -- a match on a tag means more
    than the same word buried in the body text."""
    return (
        tokenize(policy.title) * 3
        + [t for tag in policy.tags for t in tokenize(tag)] * 3
        + tokenize(policy.category) * 2
        + tokenize(policy.text)
    )


@dataclass(frozen=True)
class Hit:
    policy: Policy
    score: float

    def as_dict(self) -> dict:
        return {
            "policy_id": self.policy.id,
            "title": self.policy.title,
            "text": self.policy.text,
            "severity": self.policy.severity,
            "category": self.policy.category,
            "score": round(self.score, 4),
        }


class PolicyIndex:
    """A TF-IDF index over a policy corpus."""

    def __init__(self, policies: tuple[Policy, ...] = POLICIES) -> None:
        self.policies = policies
        self._df: Counter[str] = Counter()
        self._vectors: list[dict[str, float]] = []

        term_lists = [_policy_terms(p) for p in policies]
        for terms in term_lists:
            self._df.update(set(terms))

        n = len(policies)
        for terms in term_lists:
            self._vectors.append(self._vectorize(Counter(terms), n))

    def _idf(self, term: str, n: int) -> float:
        # Smoothed idf; a query term absent from the corpus gets the weight of a
        # term seen once rather than dividing by zero.
        return math.log((n + 1) / (self._df.get(term, 0) + 1)) + 1.0

    def _vectorize(self, counts: Counter[str], n: int) -> dict[str, float]:
        vec = {term: (1 + math.log(tf)) * self._idf(term, n) for term, tf in counts.items()}
        norm = math.sqrt(sum(w * w for w in vec.values()))
        if norm == 0:
            return {}
        return {term: w / norm for term, w in vec.items()}

    def search(self, query: str, k: int = 3, min_score: float = 0.01) -> list[Hit]:
        """Top `k` policies for a free-text query, best first.

        Returns [] for an empty or all-stopword query rather than the whole
        library -- an empty question has no answer, not every answer.
        """
        terms = tokenize(query)
        if not terms:
            return []
        q = self._vectorize(Counter(terms), len(self.policies))

        hits = []
        for policy, vec in zip(self.policies, self._vectors):
            score = sum(w * vec.get(term, 0.0) for term, w in q.items())
            if score > min_score:
                hits.append(Hit(policy=policy, score=score))
        # Ties break on policy id so the same question always returns the same
        # order -- an audit trail that reshuffles is not an audit trail.
        hits.sort(key=lambda h: (-h.score, h.policy.id))
        return hits[:k]


@functools.lru_cache(maxsize=1)
def default_index() -> PolicyIndex:
    return PolicyIndex()


def search(query: str, k: int = 3) -> list[Hit]:
    """Search the shipped control library."""
    return default_index().search(query, k=k)
