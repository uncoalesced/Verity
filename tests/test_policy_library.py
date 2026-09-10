"""The control library. Cheap to test, but an id typo or a severity out of
order here silently changes what every downstream verdict means."""

import pytest

from verity.policy.library import (
    BY_ID,
    HIGH,
    INFO,
    LOW,
    MEDIUM,
    POLICIES,
    SEVERITY_ORDER,
    get,
    severity_rank,
)


def test_severity_order_is_ascending_by_consequence():
    assert SEVERITY_ORDER == (INFO, LOW, MEDIUM, HIGH)
    assert severity_rank(INFO) < severity_rank(LOW) < severity_rank(MEDIUM) < severity_rank(HIGH)


def test_get_returns_the_policy():
    policy = get("P-001")
    assert policy.id == "P-001"
    assert policy.title


def test_get_raises_keyerror_on_unknown_id():
    with pytest.raises(KeyError):
        get("P-999")


def test_policy_ids_are_unique():
    ids = [p.id for p in POLICIES]
    assert len(ids) == len(set(ids))


def test_by_id_matches_policies():
    assert set(BY_ID) == {p.id for p in POLICIES}
    for policy_id, policy in BY_ID.items():
        assert policy.id == policy_id


def test_every_policy_has_a_valid_severity_and_nonempty_text():
    valid = set(SEVERITY_ORDER)
    for policy in POLICIES:
        assert policy.severity in valid
        assert policy.text.strip()
        assert policy.title.strip()
        assert policy.category.strip()


def test_every_rule_cited_in_rules_py_exists_in_the_library():
    """rules.py cites policy ids by string; a typo there would raise KeyError at
    audit time, not at import time. Cross-check the two modules agree here."""
    import re
    from pathlib import Path

    rules_source = (Path(__file__).parent.parent / "src" / "verity" / "policy" / "rules.py").read_text()
    cited = set(re.findall(r'library\.get\("(P-\d+)"\)', rules_source))
    assert cited  # the regex itself did not silently match nothing
    assert cited <= set(BY_ID)
