"""The one place Verity talks to a language model.

Everything else in the system is deterministic on purpose -- the rules, the
verdict, the arithmetic. The model does exactly one job here, and it is a job
the deterministic engine genuinely cannot do for itself: checking that the
policy sentence quoted on a finding actually supports the claim the finding
makes. See `verity.llm.citation_check`.

Nothing in this package is allowed to change a verdict.
"""

from verity.llm.client import (
    DEFAULT_MODEL,
    LLMResponse,
    LLMUnavailable,
    Prompt,
    available,
    complete,
    load_prompt,
)

__all__ = [
    "DEFAULT_MODEL",
    "LLMResponse",
    "LLMUnavailable",
    "Prompt",
    "available",
    "complete",
    "load_prompt",
]
