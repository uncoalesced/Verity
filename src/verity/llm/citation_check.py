"""Does the policy we quoted actually say what we claimed it says?

Every finding Verity emits carries a policy id and a quoted passage. The
deterministic engine cannot check that pairing -- `_finding()` copies the text
off the policy the rule names, so the rule and the citation agree with each
other by construction, and would go on agreeing if the rule cited the wrong
policy entirely. Nothing inside the engine can see that mistake.

That is the gap this fills, and it is the only place in Verity a model is
allowed to have an opinion. Claude is shown one finding and the policy text it
quoted, and asked one question: does that text support that claim.

Three rules about what this is allowed to do:

* **It never changes a verdict.** A failed citation check produces a warning on
  the run, for whoever maintains the control library. The finding stands, the
  verdict stands, and payment routing is unchanged. Letting a model overrule a
  deterministic control would give back exactly the auditability the rest of the
  system is built to keep.
* **It is optional.** With no API key configured the check reports itself as
  skipped. It does not fall back to a guess, and a skipped check never reads as
  a passed one.
* **A model failure is a failed check, not a passed one.** If the call raises or
  the reply cannot be parsed, the result is `error`, which is reported -- not
  quietly rounded to "fine".
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

from verity.llm.client import LLMUnavailable, available, complete, load_prompt
from verity.obs.cost import Usage, total
from verity.policy.rules import Finding

log = logging.getLogger(__name__)

PROMPT_NAME = "citation_check.v1"

SUPPORTED = "supported"
UNSUPPORTED = "unsupported"
SKIPPED = "skipped"
ERROR = "error"

_VERDICT = re.compile(r"(?im)^\s*VERDICT:\s*(SUPPORTED|UNSUPPORTED)\b")
_REASON = re.compile(r"(?im)^\s*REASON:\s*(.+)$")


@dataclass(frozen=True)
class CitationCheck:
    """The result of checking one finding's citation."""

    rule_id: str
    result: str
    reason: str = ""
    prompt_version: str = ""
    model: str = ""
    usage: Usage = field(default_factory=Usage)

    @property
    def faithful(self) -> bool:
        """True only on an explicit SUPPORTED. Skipped and error are not passes."""
        return self.result == SUPPORTED

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "result": self.result,
            "reason": self.reason,
            "prompt_version": self.prompt_version,
            "model": self.model,
            "usage": self.usage.as_dict(),
        }


@dataclass
class CitationReport:
    """Every citation check for one document, plus what the lot cost."""

    checks: list[CitationCheck] = field(default_factory=list)

    @property
    def usage(self) -> Usage:
        return total([c.usage for c in self.checks])

    @property
    def unsupported(self) -> list[CitationCheck]:
        return [c for c in self.checks if c.result == UNSUPPORTED]

    @property
    def ran(self) -> int:
        return sum(1 for c in self.checks if c.result in (SUPPORTED, UNSUPPORTED))

    @property
    def faithfulness(self) -> float | None:
        """Share of checks that came back supported, or None if none ran.

        None rather than 1.0 on an empty run. A document nobody checked has no
        faithfulness score, and reporting a perfect one would be a lie of the
        most convenient kind.
        """
        if not self.ran:
            return None
        return sum(1 for c in self.checks if c.faithful) / self.ran

    def as_dict(self) -> dict:
        score = self.faithfulness
        return {
            "checks": [c.as_dict() for c in self.checks],
            "ran": self.ran,
            "unsupported": [c.rule_id for c in self.unsupported],
            "faithfulness": None if score is None else round(score, 4),
            "usage": self.usage.as_dict(),
        }


def _parse(text: str) -> tuple[str, str]:
    """Read the two-line reply. An unparseable reply is an error, not a pass."""
    verdict = _VERDICT.search(text)
    if not verdict:
        return ERROR, f"could not parse a verdict from: {text[:120]!r}"
    reason = _REASON.search(text)
    return verdict.group(1).lower(), (reason.group(1).strip() if reason else "")


def check_finding(finding: Finding) -> CitationCheck:
    """Ask whether this finding's quoted policy supports its claim."""
    if not finding.policy_text:
        return CitationCheck(
            rule_id=finding.rule_id,
            result=SKIPPED,
            reason="the finding quotes no policy text",
        )
    if not available():
        return CitationCheck(
            rule_id=finding.rule_id,
            result=SKIPPED,
            reason="no ANTHROPIC_API_KEY configured",
        )

    prompt = load_prompt(PROMPT_NAME)
    try:
        response = complete(
            prompt,
            rule_id=finding.rule_id,
            finding=finding.message,
            evidence=json.dumps(finding.evidence, default=str),
            policy_title=finding.policy_title,
            policy_text=finding.policy_text,
        )
    except LLMUnavailable as exc:
        return CitationCheck(rule_id=finding.rule_id, result=SKIPPED, reason=str(exc))
    except Exception as exc:  # noqa: BLE001 - a broken check must be visible, not fatal
        log.warning("citation check failed for %s: %s", finding.rule_id, exc)
        return CitationCheck(
            rule_id=finding.rule_id,
            result=ERROR,
            reason=f"{type(exc).__name__}: {exc}",
            prompt_version=prompt.version,
        )

    result, reason = _parse(response.text)
    return CitationCheck(
        rule_id=finding.rule_id,
        result=result,
        reason=reason,
        prompt_version=response.prompt_version,
        model=response.model,
        usage=response.usage,
    )


def check_findings(findings: list[Finding]) -> CitationReport:
    """Check every finding on one document."""
    return CitationReport(checks=[check_finding(f) for f in findings])
