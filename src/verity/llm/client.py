"""Talking to Claude, with the prompt on disk and the bill on the record.

Three things this wrapper is responsible for, none of them exciting and all of
them the reason it exists rather than calling the SDK inline:

**The prompt is a file, not a string literal.** `prompts/citation_check.v1.md`
is a versioned artefact with its model and limits in its own header. A prompt
buried in Python is a prompt nobody can diff, review, or roll back, and "we
changed the wording and the numbers moved" is not a sentence worth saying
without being able to point at the two versions. `load_prompt` reads them, and
every result carries the version that produced it.

There is one version so far, so there is no A/B harness yet -- a comparison
between two prompt versions needs a second version and an API budget to run it
against, and building the harness before either exists would be scaffolding
pretending to be a measurement. Adding `citation_check.v2.md` and scoring the
pair is the next step, not a missing one.

**Every call comes back priced.** `LLMResponse` carries the token counts and
what they cost (`verity.obs.cost`), so a per-document and per-batch figure is
addition rather than estimation.

**Absence is explicit.** With no API key configured, `available()` is False and
`complete()` raises `LLMUnavailable`. It never silently degrades to a canned
answer -- a check that quietly did not run must never look like a check that
passed, which is the same rule the trace enforces for every other step.
"""

from __future__ import annotations

import functools
import os
import re
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from verity.obs.cost import Usage, usage_for

# The default is deliberately the strong model. This call is the only place a
# model touches an audit, it runs once per finding rather than once per token of
# a document, and the failure it exists to catch -- a finding quoting policy that
# does not support it -- is exactly the failure a cheaper judge would wave
# through. Override with VERITY_LLM_MODEL.
DEFAULT_MODEL = "claude-opus-5"

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"

_HEADER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
_SECTION = re.compile(r"^# (System|User)\s*$", re.MULTILINE)


class LLMUnavailable(RuntimeError):
    """No API key configured, or the SDK is not installed."""


@dataclass(frozen=True)
class Prompt:
    """One versioned prompt, loaded off disk.

    `version` is part of the artefact, not derived from the filename, so a
    result carrying `prompt_version="citation-check-v1"` can be traced to the
    exact text that produced it.
    """

    name: str
    version: str
    system: str
    template: str
    model: str = DEFAULT_MODEL
    max_tokens: int = 1024
    effort: str = "low"

    def render(self, **values) -> str:
        """Fill the user template. Missing keys are an error, not a blank."""
        return self.template.format(**values)


@dataclass(frozen=True)
class LLMResponse:
    """What one call produced, and what it cost."""

    text: str
    model: str
    prompt_version: str
    usage: Usage
    latency_ms: float
    stop_reason: str | None = None

    @property
    def cost_usd(self) -> Decimal:
        return self.usage.cost_usd

    def as_dict(self) -> dict:
        return {
            "model": self.model,
            "prompt_version": self.prompt_version,
            "latency_ms": round(self.latency_ms, 2),
            "stop_reason": self.stop_reason,
            "usage": self.usage.as_dict(),
        }


def _parse_header(text: str) -> tuple[dict, str]:
    """Split the `---` header off a prompt file.

    A deliberately small parser rather than a YAML dependency: the header is
    four scalar keys, and adding a parser for that is more moving parts than the
    thing it parses.
    """
    match = _HEADER.match(text)
    if not match:
        return {}, text
    header = {}
    for line in match.group(1).splitlines():
        if not line.strip() or ":" not in line:
            continue
        key, _, value = line.partition(":")
        header[key.strip()] = value.strip()
    return header, text[match.end() :]


def _split_sections(body: str) -> tuple[str, str]:
    """Pull the `# System` and `# User` halves out of a prompt file."""
    parts = _SECTION.split(body)
    sections = {}
    # split() yields [preamble, "System", text, "User", text, ...]
    for label, text in zip(parts[1::2], parts[2::2]):
        sections[label.lower()] = text.strip()
    return sections.get("system", ""), sections.get("user", "")


@functools.lru_cache(maxsize=8)
def load_prompt(name: str) -> Prompt:
    """Load `prompts/<name>.md`, e.g. `load_prompt("citation_check.v1")`."""
    path = PROMPT_DIR / f"{name}.md"
    if not path.exists():
        raise FileNotFoundError(f"no prompt named {name} in {PROMPT_DIR}")
    header, body = _parse_header(path.read_text(encoding="utf-8"))
    system, template = _split_sections(body)
    return Prompt(
        name=name,
        version=header.get("version", name),
        system=system,
        template=template,
        model=header.get("model", DEFAULT_MODEL),
        max_tokens=int(header.get("max_tokens", 1024)),
        effort=header.get("effort", "low"),
    )


def model_id() -> str:
    """The model a call would use, before any per-prompt override."""
    return os.getenv("VERITY_LLM_MODEL") or DEFAULT_MODEL


def available() -> bool:
    """True when a call would actually reach Claude.

    Checked before the citation step runs, so "not configured" is reported as
    not configured rather than surfacing as a failed step in every trace.
    """
    if not os.getenv("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


@functools.lru_cache(maxsize=1)
def _client():
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - the dependency is declared
        raise LLMUnavailable("the anthropic SDK is not installed") from exc
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise LLMUnavailable("ANTHROPIC_API_KEY is not set")
    return anthropic.Anthropic()


def complete(prompt: Prompt, *, model: str | None = None, **values) -> LLMResponse:
    """Render `prompt` with `values`, send it, and return the priced result."""
    chosen = model or os.getenv("VERITY_LLM_MODEL") or prompt.model
    rendered = prompt.render(**values)

    client = _client()
    clock = time.perf_counter()
    message = client.messages.create(
        model=chosen,
        max_tokens=prompt.max_tokens,
        system=prompt.system,
        output_config={"effort": prompt.effort},
        messages=[{"role": "user", "content": rendered}],
    )
    latency_ms = (time.perf_counter() - clock) * 1000

    text = "".join(block.text for block in message.content if block.type == "text")
    usage = usage_for(
        chosen,
        input_tokens=message.usage.input_tokens,
        output_tokens=message.usage.output_tokens,
        cache_read_tokens=getattr(message.usage, "cache_read_input_tokens", 0) or 0,
    )
    return LLMResponse(
        text=text.strip(),
        model=chosen,
        prompt_version=prompt.version,
        usage=usage,
        latency_ms=latency_ms,
        stop_reason=message.stop_reason,
    )
