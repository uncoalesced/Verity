"""What a model call cost, in tokens and in money.

A deterministic pipeline has no per-token cost, which is why this module did not
exist until there was an actual model call to account for. Now that the citation
check (`verity.llm.citation_check`) sends policy text to Claude, three numbers
matter per document and per batch: how many tokens went out, how many came back,
and what that came to in dollars.

Prices are recorded *on the run*, not looked up when a report is drawn. A price
list changes; an audit that says a document cost $0.0021 to check has to keep
saying that afterwards.

ponytail: a hard-coded table, not a pricing API call. Published rates change on
the order of months and a wrong number here is visible in the next report; a
network call in the middle of an audit is not worth the failure mode.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

# USD per million tokens, as published for the first-party Anthropic API.
# Source: the bundled claude-api reference, model table cached 2026-06-24.
PRICING: dict[str, tuple[Decimal, Decimal]] = {
    "claude-opus-5": (Decimal("5.00"), Decimal("25.00")),
    "claude-opus-4-8": (Decimal("5.00"), Decimal("25.00")),
    "claude-sonnet-5": (Decimal("2.00"), Decimal("10.00")),
    "claude-haiku-4-5": (Decimal("1.00"), Decimal("5.00")),
    "claude-fable-5-1": (Decimal("10.00"), Decimal("50.00")),
}

MILLION = Decimal("1000000")
# Sub-cent precision: one citation check costs well under a cent, and rounding to
# cents would report every call as free.
USD = Decimal("0.000001")


def price_of(model: str) -> tuple[Decimal, Decimal] | None:
    """Input and output price per million tokens, or None for an unknown model."""
    return PRICING.get(model)


def cost_usd(model: str, input_tokens: int, output_tokens: int) -> Decimal | None:
    """What this call cost, or None when the model is not in the table.

    None rather than zero, deliberately. A model whose price nobody knows costs
    an unknown amount, and reporting that as free is the kind of quietly wrong
    number that turns up in a budget review six months later.
    """
    price = price_of(model)
    if price is None:
        return None
    input_price, output_price = price
    total_cost = (Decimal(input_tokens) * input_price + Decimal(output_tokens) * output_price) / MILLION
    return total_cost.quantize(USD)


@dataclass
class Usage:
    """Token and money totals for one call, or for a run of them.

    Additive: `Usage() + call_a + call_b` is the batch total. `cost_usd` is
    carried rather than recomputed on read, so a total stays what it was when
    the calls were made even if the price table moves underneath it.
    """

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cost_usd: Decimal = field(default_factory=lambda: Decimal("0"))
    # Counts calls on a model with no published price, so a dollar figure is
    # never quoted as complete when part of it is unknown.
    unpriced_calls: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def priced(self) -> bool:
        """False when some call could not be priced -- read `cost_usd` as a floor."""
        return self.unpriced_calls == 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            calls=self.calls + other.calls,
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_tokens=self.cache_read_tokens + other.cache_read_tokens,
            cost_usd=self.cost_usd + other.cost_usd,
            unpriced_calls=self.unpriced_calls + other.unpriced_calls,
        )

    def as_dict(self) -> dict:
        return {
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "total_tokens": self.total_tokens,
            "cost_usd": str(self.cost_usd),
            "fully_priced": self.priced,
        }


def usage_for(model: str, input_tokens: int, output_tokens: int, cache_read_tokens: int = 0) -> Usage:
    """The `Usage` for one completed call."""
    cost = cost_usd(model, input_tokens, output_tokens)
    return Usage(
        calls=1,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_tokens=cache_read_tokens,
        cost_usd=cost if cost is not None else Decimal("0"),
        unpriced_calls=0 if cost is not None else 1,
    )


def total(usages: list[Usage]) -> Usage:
    """Sum a run of calls -- one document's checks, or a whole batch."""
    running = Usage()
    for usage in usages:
        running = running + usage
    return running
