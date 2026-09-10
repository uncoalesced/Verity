"""What the agent is allowed to do.

The loop never calls a model or the database directly. It calls tools out of a
`Toolbox`, and every tool is a plain callable that can be swapped. That is not
architecture for its own sake -- it is what lets a whole audit run inside a test
in milliseconds against fixed inputs, which is the only honest way to check that
the decision logic does what the policy says it does.

The defaults are the real thing: real triage, the real extraction models, the
real history lookup.
"""

from __future__ import annotations

import io
import logging
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from PIL import Image

from verity.extraction.schema import ExtractedFields
from verity.ingestion import router
from verity.policy.retrieval import Hit
from verity.policy.retrieval import search as policy_search
from verity.policy.rules import PriorDocument

log = logging.getLogger(__name__)


class PageLoadError(RuntimeError):
    """The file passed triage but no page image could be produced from it."""


def load_page_image(path: str | Path) -> Image.Image:
    """Get the first page of a document as an image the models can read.

    ponytail: for PDFs this pulls the embedded page image rather than
    rasterising. That covers scanned PDFs, which is what an expense pipeline
    actually receives. A born-digital, vector-text PDF has no embedded image and
    raises -- add pymupdf and rasterise when those show up in the corpus.
    """
    path = Path(path)
    with path.open("rb") as fh:
        head = fh.read(16)

    if router.sniff_format(head) == router.PDF:
        from pypdf import PdfReader

        reader = PdfReader(path)
        for page in reader.pages:
            for embedded in page.images:
                return Image.open(io.BytesIO(embedded.data)).convert("RGB")
        raise PageLoadError(
            f"{path.name}: PDF carries no embedded page image "
            "(born-digital PDFs are not rasterised yet)"
        )
    return Image.open(path).convert("RGB")


def _default_read_fields(image: Image.Image, dayfirst: bool = False) -> ExtractedFields:
    # Imported inside the call so that importing the agent does not pull in
    # torch and trigger a checkpoint download.
    from verity.extraction.structured import extract

    return extract(image, dayfirst=dayfirst)


def _default_read_field(image: Image.Image, field_name: str, question: str | None = None) -> str:
    from verity.extraction.document_qa import extract_field

    return extract_field(image, field_name, question=question)


def _default_detect_signature(image: Image.Image) -> tuple[bool, float]:
    from verity.extraction.object_detection import detect_signature

    return detect_signature(image)


def _no_history(fields: ExtractedFields) -> list[PriorDocument]:
    """No ledger configured.

    The cross-document controls then have nothing to compare against. The loop
    records that in the trace rather than letting an unchecked control read as a
    clean pass.
    """
    return []


@dataclass
class Toolbox:
    """The agent's capabilities, each one replaceable.

    `history` is the tool that reaches outside the document: given the fields
    just read, it returns previously filed documents worth comparing against.
    The database-backed version lives in `verity.agent.history`.
    """

    triage: Callable[[str | Path], router.TriageResult] = router.route
    load_image: Callable[[str | Path], Image.Image] = load_page_image
    read_fields: Callable[..., ExtractedFields] = _default_read_fields
    read_field: Callable[..., str] = _default_read_field
    detect_signature: Callable[[Image.Image], tuple[bool, float]] = _default_detect_signature
    history: Callable[[ExtractedFields], list[PriorDocument]] = _no_history
    search_policies: Callable[..., list[Hit]] = policy_search
    # Set False to keep the loop off the object-detection model entirely, for
    # example in a batch run where signatures are checked separately.
    signature_detection_enabled: bool = True


def default_toolbox(**overrides) -> Toolbox:
    return Toolbox(**overrides)


def with_history(toolbox: Toolbox, history) -> Toolbox:
    """Bind a ledger lookup, unless the caller already supplied one.

    The cross-document controls -- duplicate payment (P-002) and threshold
    splitting (P-011) -- can only fire if something hands the loop the documents
    already on file. `Toolbox.history` defaults to `_no_history`, so a caller
    that forgets to bind a real ledger gets two controls that silently never
    fire. This is how the API and the batch runner connect it; a test that
    injected its own history keeps it.
    """
    if toolbox.history is not _no_history:
        return toolbox
    return replace(toolbox, history=history)


def history_from_documents(rows: list[PriorDocument]) -> Callable[[ExtractedFields], list[PriorDocument]]:
    """A fixed ledger, for tests, demos and the offline policy eval."""

    def lookup(fields: ExtractedFields) -> list[PriorDocument]:
        return list(rows)

    return lookup
