"""Sending the trace somewhere an LLMOps tool can read it.

`Trace` already records every step, its arguments, its result, how long it took
and whether it failed. That is the audit trail, it is what gets persisted to
`trace_steps`, and none of it changes here. What was missing was a way to get
the same tree into a tool built for looking at runs across time -- latency
distributions, failure rates, cost per document.

So this is a *wrapper*, not a rewrite. `Trace.as_dict()` already has the shape
of a span tree; `export_trace` walks it and emits one Langfuse span per step.
Verity does not depend on Langfuse being there:

* Not configured (no keys in the environment) -> `enabled()` is False,
  `export_trace` returns False, and the audit is completely unaffected.
* Configured but broken (network down, bad key) -> the failure is logged and
  swallowed. An observability backend that is down must never fail an audit
  that otherwise succeeded. This is the one place in the codebase where
  swallowing an exception is right, because the thing being lost is a
  diagnostic copy, not the diagnostic itself -- the real trace is already on
  the `AuditResult` and already in the database.

Set up with:
    uv sync --extra obs
    export LANGFUSE_PUBLIC_KEY=... LANGFUSE_SECRET_KEY=... LANGFUSE_HOST=...
"""

from __future__ import annotations

import functools
import logging
import os

from verity.obs.cost import Usage
from verity.obs.trace import Trace

log = logging.getLogger(__name__)

REQUIRED_ENV = ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY")


class LangfuseUnavailable(RuntimeError):
    """Langfuse is not configured, or the SDK is not installed."""


def enabled() -> bool:
    """True when a trace would actually be shipped."""
    if not all(os.getenv(name) for name in REQUIRED_ENV):
        return False
    try:
        import langfuse  # noqa: F401
    except ImportError:
        return False
    return True


@functools.lru_cache(maxsize=1)
def _client():
    try:
        from langfuse import Langfuse
    except ImportError as exc:
        raise LangfuseUnavailable("langfuse is not installed (uv sync --extra obs)") from exc
    missing = [name for name in REQUIRED_ENV if not os.getenv(name)]
    if missing:
        raise LangfuseUnavailable(f"not configured: {', '.join(missing)}")
    return Langfuse(
        public_key=os.environ["LANGFUSE_PUBLIC_KEY"],
        secret_key=os.environ["LANGFUSE_SECRET_KEY"],
        host=os.getenv("LANGFUSE_HOST") or None,
    )


def trace_payload(
    trace: Trace, *, verdict: str = "", filename: str = "", usage: Usage | None = None
) -> dict:
    """The trace as Langfuse wants it, without sending anything.

    Separated from the sending so the mapping can be tested without a server,
    which is the only part of this worth testing.
    """
    data = trace.as_dict()
    payload = {
        "name": "verity.audit",
        "session_id": data["run_id"],
        "metadata": {
            "document_id": data["document_id"],
            "filename": filename,
            "verdict": verdict,
            "duration_ms": data["duration_ms"],
            "failed_steps": [s.tool for s in trace.failed_steps],
        },
        "spans": [
            {
                "name": step["tool"],
                "input": step["args"],
                "output": step["result"],
                "level": "DEFAULT" if step["ok"] else "ERROR",
                "status_message": step["error"] or step["note"],
                "metadata": {"index": step["index"], "duration_ms": step["duration_ms"]},
            }
            for step in data["steps"]
        ],
    }
    if usage is not None and usage.calls:
        payload["metadata"]["llm"] = usage.as_dict()
    return payload


def export_trace(
    trace: Trace, *, verdict: str = "", filename: str = "", usage: Usage | None = None
) -> bool:
    """Ship one trace. Returns False when nothing was sent, never raises."""
    if not enabled():
        return False

    payload = trace_payload(trace, verdict=verdict, filename=filename, usage=usage)
    try:
        client = _client()
        with client.start_as_current_span(name=payload["name"]) as root:
            root.update_trace(
                session_id=payload["session_id"],
                metadata=payload["metadata"],
                output={"verdict": verdict},
            )
            for span in payload["spans"]:
                with client.start_as_current_span(name=span["name"]) as child:
                    child.update(
                        input=span["input"],
                        output=span["output"],
                        level=span["level"],
                        status_message=span["status_message"],
                        metadata=span["metadata"],
                    )
        client.flush()
    except Exception as exc:  # noqa: BLE001
        # Deliberate. See the module docstring: losing a diagnostic copy must
        # never fail the audit that produced it.
        log.warning("could not export trace %s to Langfuse: %s", trace.run_id, exc)
        return False
    return True
