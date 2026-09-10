"""The audit trail of the audit.

An agent that decides things has to be able to show its working. Every step the
loop takes -- which tool it called, what it passed, what came back, how long it
took, whether it failed -- lands in a `Trace`. The trace is what gets shown to a
reviewer who asks "why was this invoice held?" and what gets kept for whoever
asks the same question a year later.

Two properties matter more than richness here:

* A failing step is recorded, not swallowed. The step is marked `ok=False` with
  the error text, and the loop decides what to do about it. An audit that
  quietly skipped a control must never look like an audit that ran it.
* Results are summarised into plain data. Nothing in a trace holds a model, an
  open file or a database handle, so a trace can always be serialised and kept.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field

log = logging.getLogger("verity.trace")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _jsonable(value: object, _depth: int = 0) -> object:
    """Best-effort conversion to something `json.dumps` accepts.

    Traces are diagnostics: an unserialisable value becomes its repr rather than
    blowing up the audit that produced it.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if _depth > 6:
        return repr(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v, _depth + 1) for v in value]
    if isinstance(value, (dt.date, dt.datetime)):
        return value.isoformat()
    if hasattr(value, "as_dict"):
        return _jsonable(value.as_dict(), _depth + 1)
    return str(value)


@dataclass
class Step:
    """One tool call by the agent."""

    index: int
    tool: str
    args: dict = field(default_factory=dict)
    result: object = None
    ok: bool = True
    error: str | None = None
    duration_ms: float = 0.0
    started_at: dt.datetime = field(default_factory=_now)
    # Why the agent chose this step. Free text, written for a human reviewer.
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "tool": self.tool,
            "args": _jsonable(self.args),
            "result": _jsonable(self.result),
            "ok": self.ok,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
            "started_at": self.started_at.isoformat(),
            "note": self.note,
        }


class Trace:
    """An ordered record of one audit run."""

    def __init__(self, document_id: int | None = None, run_id: str | None = None) -> None:
        self.run_id = run_id or uuid.uuid4().hex
        self.document_id = document_id
        self.started_at = _now()
        self.finished_at: dt.datetime | None = None
        self.steps: list[Step] = []

    @contextmanager
    def step(self, tool: str, args: dict | None = None, note: str = ""):
        """Time one tool call and record how it went.

        The step is appended before the body runs, so a call that raises still
        appears in the trace. The exception propagates -- the loop, not the
        recorder, decides whether a failed tool is fatal.
        """
        record = Step(index=len(self.steps) + 1, tool=tool, args=args or {}, note=note)
        self.steps.append(record)
        clock = time.perf_counter()
        try:
            yield record
        except Exception as exc:
            record.ok = False
            record.error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            record.duration_ms = (time.perf_counter() - clock) * 1000
            log.debug(
                "run=%s step=%d tool=%s ok=%s %.1fms",
                self.run_id,
                record.index,
                record.tool,
                record.ok,
                record.duration_ms,
            )

    def finish(self) -> Trace:
        self.finished_at = _now()
        return self

    @property
    def duration_ms(self) -> float:
        end = self.finished_at or _now()
        return (end - self.started_at).total_seconds() * 1000

    @property
    def failed_steps(self) -> list[Step]:
        return [s for s in self.steps if not s.ok]

    def as_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "document_id": self.document_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms": round(self.duration_ms, 2),
            "steps": [s.as_dict() for s in self.steps],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent)
