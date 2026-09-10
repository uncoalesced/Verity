"""The model step, checked without ever calling the model.

Every test here runs against a fake client. That is not a shortcut -- the things
worth checking are the ones that decide what an operator sees when the call goes
wrong: an unparseable reply, a missing key, a raised exception. A test that
needed a real API call could not cover any of them reliably, and would cost
money to run.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import pytest

from verity.llm import citation_check, client
from verity.llm.client import LLMUnavailable, Prompt
from verity.obs import cost
from verity.policy import library
from verity.policy.rules import Finding

# --- pricing ---------------------------------------------------------------


def test_cost_is_computed_from_the_published_rate():
    # 1M in + 1M out on Opus 5 at $5 / $25.
    assert cost.cost_usd("claude-opus-5", 1_000_000, 1_000_000) == Decimal("30.000000")


def test_small_calls_keep_sub_cent_precision():
    """A citation check costs a fraction of a cent. Rounding to cents would
    report every call as free."""
    price = cost.cost_usd("claude-opus-5", 1200, 80)
    assert price is not None
    assert Decimal("0") < price < Decimal("0.01")


def test_an_unpriced_model_costs_unknown_not_zero():
    assert cost.cost_usd("some-model-nobody-priced", 1000, 1000) is None
    usage = cost.usage_for("some-model-nobody-priced", 1000, 1000)
    assert usage.priced is False
    assert usage.as_dict()["fully_priced"] is False


def test_usage_adds_up_across_calls():
    a = cost.usage_for("claude-opus-5", 1000, 100)
    b = cost.usage_for("claude-opus-5", 2000, 200)
    combined = cost.total([a, b])
    assert combined.calls == 2
    assert combined.input_tokens == 3000
    assert combined.output_tokens == 300
    assert combined.cost_usd == a.cost_usd + b.cost_usd
    assert combined.priced


def test_a_total_containing_an_unpriced_call_is_not_fully_priced():
    combined = cost.total([cost.usage_for("claude-opus-5", 10, 10), cost.usage_for("mystery", 10, 10)])
    assert combined.priced is False


# --- the prompt on disk ----------------------------------------------------


def test_the_shipped_prompt_loads_with_its_version_and_limits():
    prompt = client.load_prompt(citation_check.PROMPT_NAME)
    assert prompt.version == "citation-check-v1"
    assert prompt.model in cost.PRICING, "the prompt names a model with no published price"
    assert prompt.system
    assert prompt.max_tokens > 0


def test_the_prompt_template_carries_every_field_the_check_fills():
    prompt = client.load_prompt(citation_check.PROMPT_NAME)
    for placeholder in ("{rule_id}", "{finding}", "{evidence}", "{policy_title}", "{policy_text}"):
        assert placeholder in prompt.template


def test_render_refuses_to_silently_leave_a_placeholder_empty():
    prompt = Prompt(name="t", version="t", system="s", template="{a} and {b}")
    with pytest.raises(KeyError):
        prompt.render(a="x")


# --- the check itself ------------------------------------------------------


def _finding(**overrides) -> Finding:
    policy = library.get("P-009")
    base = {
        "rule_id": policy.id,
        "severity": policy.severity,
        "message": "Amount 18432.75 exceeds the delegated approval limit of 10000.00.",
        "evidence": {"total": "18432.75"},
        "policy_title": policy.title,
        "policy_text": policy.text,
    }
    base.update(overrides)
    return Finding(**base)


def _reply(text: str, input_tokens: int = 900, output_tokens: int = 30):
    """A stand-in for one `messages.create` response."""
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        usage=SimpleNamespace(
            input_tokens=input_tokens, output_tokens=output_tokens, cache_read_input_tokens=0
        ),
        stop_reason="end_turn",
    )


@pytest.fixture
def fake_llm(monkeypatch):
    """Wire `complete` to a scripted reply instead of the network."""

    def install(text: str):
        fake = SimpleNamespace(messages=SimpleNamespace(create=lambda **kwargs: _reply(text)))
        monkeypatch.setattr(client, "_client", lambda: fake)
        monkeypatch.setattr(client, "available", lambda: True)
        monkeypatch.setattr(citation_check, "available", lambda: True)
        monkeypatch.setenv("VERITY_LLM_MODEL", "claude-opus-5")

    return install


def test_a_supported_citation_comes_back_faithful(fake_llm):
    fake_llm("VERDICT: SUPPORTED\nREASON: The policy states the delegated limit the finding relies on.")
    check = citation_check.check_finding(_finding())
    assert check.result == citation_check.SUPPORTED
    assert check.faithful
    assert check.prompt_version == "citation-check-v1"
    assert check.usage.calls == 1
    assert check.usage.cost_usd > 0


def test_an_unsupported_citation_is_reported_with_its_reason(fake_llm):
    fake_llm("VERDICT: UNSUPPORTED\nREASON: The quoted policy is about duplicate payments.")
    check = citation_check.check_finding(_finding())
    assert check.result == citation_check.UNSUPPORTED
    assert check.faithful is False
    assert "duplicate payments" in check.reason


def test_an_unparseable_reply_is_an_error_not_a_pass(fake_llm):
    """The failure mode that matters: a check that did not work must never
    read as a check that passed."""
    fake_llm("I think that looks fine to me!")
    check = citation_check.check_finding(_finding())
    assert check.result == citation_check.ERROR
    assert check.faithful is False


def test_a_raising_call_is_an_error_not_a_pass(monkeypatch):
    monkeypatch.setattr(citation_check, "available", lambda: True)

    def boom(*args, **kwargs):
        raise RuntimeError("connection reset")

    monkeypatch.setattr(citation_check, "complete", boom)
    check = citation_check.check_finding(_finding())
    assert check.result == citation_check.ERROR
    assert "connection reset" in check.reason
    assert check.faithful is False


def test_no_api_key_means_skipped_not_passed(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    check = citation_check.check_finding(_finding())
    assert check.result == citation_check.SKIPPED
    assert check.faithful is False


def test_a_finding_quoting_no_policy_is_skipped():
    check = citation_check.check_finding(_finding(policy_text=""))
    assert check.result == citation_check.SKIPPED


def test_complete_refuses_to_invent_an_answer_without_a_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client._client.cache_clear()
    try:
        with pytest.raises(LLMUnavailable):
            client.complete(
                client.load_prompt(citation_check.PROMPT_NAME),
                rule_id="x",
                finding="y",
                evidence="{}",
                policy_title="t",
                policy_text="p",
            )
    finally:
        client._client.cache_clear()


# --- the report ------------------------------------------------------------


def test_faithfulness_is_none_when_nothing_ran(monkeypatch):
    """An unchecked document has no faithfulness score. Reporting 1.0 would be
    a lie of the most convenient kind."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = citation_check.check_findings([_finding(), _finding()])
    assert report.ran == 0
    assert report.faithfulness is None
    assert report.as_dict()["faithfulness"] is None


def test_faithfulness_counts_only_the_checks_that_ran(fake_llm):
    fake_llm("VERDICT: UNSUPPORTED\nREASON: unrelated policy")
    report = citation_check.check_findings([_finding(), _finding(policy_text="")])
    assert report.ran == 1
    assert report.faithfulness == 0.0
    assert [c.rule_id for c in report.unsupported] == ["P-009"]


def test_report_totals_the_cost_of_every_check(fake_llm):
    fake_llm("VERDICT: SUPPORTED\nREASON: fine")
    report = citation_check.check_findings([_finding(), _finding()])
    assert report.usage.calls == 2
    assert report.usage.cost_usd == report.checks[0].usage.cost_usd * 2
