"""Search over the control library. Enforcement never depends on this -- every
rule in rules.py runs on every document regardless -- but a reviewer's
question has to land on a sensible policy, and the same question has to land
on the same policy every time an audit is revisited."""

from __future__ import annotations

from verity.policy.library import POLICIES
from verity.policy.retrieval import PolicyIndex, default_index, search, tokenize


def test_tokenize_drops_stopwords_and_short_tokens():
    tokens = tokenize("The supplier is not on the approved list of a company")
    assert "the" not in tokens
    assert "is" not in tokens
    assert "a" not in tokens
    assert "of" not in tokens
    assert "supplier" in tokens
    assert "approved" in tokens


def test_search_finds_duplicate_payment_policy():
    hits = search("has this invoice already been paid twice", k=3)
    assert hits
    assert hits[0].policy.id == "P-002"


def test_search_surfaces_signature_policy_among_top_hits():
    hits = search("which controls cover an unsigned invoice", k=5)
    assert any(h.policy.id == "P-008" for h in hits)


def test_search_returns_at_most_k():
    hits = search("amount total date vendor supplier", k=2)
    assert len(hits) <= 2


def test_search_empty_or_all_stopword_query_returns_nothing():
    assert search("") == []
    assert search("the a of an") == []


def test_search_is_deterministic_and_ties_break_on_policy_id():
    first = search("documentation", k=5)
    second = search("documentation", k=5)
    assert [h.policy.id for h in first] == [h.policy.id for h in second]


def test_hit_as_dict_shape():
    hit = search("duplicate payment")[0]
    data = hit.as_dict()
    assert data["policy_id"] == hit.policy.id == "P-002"
    assert data["title"] == hit.policy.title
    assert 0 < data["score"] <= 1.0001  # cosine of two normalized tf-idf vectors


def test_default_index_is_a_cached_singleton():
    assert default_index() is default_index()


def test_custom_index_only_searches_its_own_corpus():
    subset = tuple(p for p in POLICIES if p.id in ("P-001", "P-002"))
    index = PolicyIndex(subset)
    hits = index.search("duplicate payment vendor amount documentation", k=5)
    assert hits
    assert all(h.policy.id in ("P-001", "P-002") for h in hits)
