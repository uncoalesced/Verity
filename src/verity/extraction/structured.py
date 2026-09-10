"""Whole-document extraction with the CORD-finetuned Donut checkpoint.

Month 1 asked the model one DocVQA question per field. That caps line-item
recall by construction: DocVQA answers with a single short span, so "what are
the items purchased?" returns one item off a twelve-line receipt no matter how
well the model can read the page. The measured cost was a line-item F1 of 0.099.

This module asks once and takes the whole structured parse -- every row, the
subtotal and the total in a single generation. Vendor and date are not in the
CORD label set, so they still come from the DocVQA head; `extract` stitches the
two readings together.

The checkpoint downloads on first use into HF_HOME (see .env).
"""

from __future__ import annotations

import functools
import logging
import re

from PIL import Image

from verity.extraction.schema import ExtractedFields, LineItem, parse_date, parse_money

log = logging.getLogger(__name__)

MODEL_ID = "naver-clova-ix/donut-base-finetuned-cord-v2"
TASK_PROMPT = "<s_cord-v2>"

# CORD's own field names, kept in one place so a schema change is one edit.
MENU = "menu"
NAME = "nm"
COUNT = "cnt"
UNIT_PRICE = "unitprice"
PRICE = "price"
SUBTOTAL = "sub_total"
SUBTOTAL_PRICE = "subtotal_price"
TAX_PRICE = "tax_price"
TOTAL = "total"
TOTAL_PRICE = "total_price"


@functools.lru_cache(maxsize=1)
def _load():
    """Load the checkpoint once per process.

    torch and transformers are imported here rather than at module scope so that
    `fields_from_cord` -- which is pure string wrangling -- can be imported and
    tested without pulling in a deep-learning stack.
    """
    import torch
    from transformers import DonutProcessor, VisionEncoderDecoderModel

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    processor = DonutProcessor.from_pretrained(MODEL_ID)
    model = VisionEncoderDecoderModel.from_pretrained(MODEL_ID).to(device).eval()
    return processor, model, device


def _as_list(value: object) -> list:
    """CORD stores a one-row table as a bare dict rather than a list of one."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def line_items_from_menu(menu: object) -> list[LineItem]:
    """Turn CORD's `menu` block into line items, dropping rows with no name."""
    items = []
    for row in _as_list(menu):
        if not isinstance(row, dict):
            continue
        name = str(row.get(NAME, "")).strip()
        if not name:
            continue
        items.append(
            LineItem(
                name=name,
                quantity=parse_money(row.get(COUNT)),
                unit_price=parse_money(row.get(UNIT_PRICE)),
                amount=parse_money(row.get(PRICE)),
            )
        )
    return items


def _nested_amount(block: object, key: str, bare_is_value: bool = True):
    """Read one money field out of a CORD sub-block, tolerating a missing block.

    `bare_is_value` covers CORD collapsing a one-field block to a bare amount:
    a bare `sub_total` *is* the subtotal, but it is not the tax, so the tax read
    passes False and gets None rather than silently inheriting the subtotal.
    """
    if isinstance(block, dict):
        return parse_money(block.get(key))
    return parse_money(block) if bare_is_value else None


def fields_from_cord(parsed: dict, confidence: float = 0.0) -> ExtractedFields:
    """Normalise one CORD parse into `ExtractedFields`.

    Pure -- no model, no I/O -- so the normalisation can be tested against
    awkward real parses without a GPU or a download.
    """
    if not isinstance(parsed, dict):
        return ExtractedFields(confidence=confidence, raw={"parse": parsed})

    return ExtractedFields(
        total=_nested_amount(parsed.get(TOTAL), TOTAL_PRICE),
        subtotal=_nested_amount(parsed.get(SUBTOTAL), SUBTOTAL_PRICE),
        # CORD prints tax inside the same sub_total block as the subtotal. It is
        # what lets P-007 check subtotal + tax == total exactly instead of
        # falling back to a tolerance band.
        tax=_nested_amount(parsed.get(SUBTOTAL), TAX_PRICE, bare_is_value=False),
        line_items=line_items_from_menu(parsed.get(MENU)),
        confidence=confidence,
        raw=parsed,
    )


def _sequence_confidence(scores: list, sequences) -> float:
    """Mean probability of the tokens the model actually chose.

    A real number off the decoder, not a constant. It answers "how sure was the
    model of what it just read", which is what P-013 routes on.
    """
    import torch

    if not scores:
        return 0.0
    # `sequences` includes the decoder prompt; scores line up with what follows.
    generated = sequences[0][-len(scores) :]
    probs = [
        torch.softmax(step[0].float(), dim=-1)[token_id].item()
        for step, token_id in zip(scores, generated)
    ]
    return float(sum(probs) / len(probs)) if probs else 0.0


def parse_document(image: Image.Image) -> ExtractedFields:
    """Read one page in a single generation. Amounts and rows only."""
    import torch

    processor, model, device = _load()

    pixel_values = processor(image.convert("RGB"), return_tensors="pt").pixel_values.to(device)
    decoder_input_ids = processor.tokenizer(
        TASK_PROMPT, add_special_tokens=False, return_tensors="pt"
    ).input_ids.to(device)

    with torch.no_grad():
        outputs = model.generate(
            pixel_values,
            decoder_input_ids=decoder_input_ids,
            max_length=model.decoder.config.max_position_embeddings,
            pad_token_id=processor.tokenizer.pad_token_id,
            eos_token_id=processor.tokenizer.eos_token_id,
            bad_words_ids=[[processor.tokenizer.unk_token_id]],
            use_cache=True,
            return_dict_in_generate=True,
            output_scores=True,
        )

    seq = processor.batch_decode(outputs.sequences)[0]
    seq = seq.replace(processor.tokenizer.eos_token, "").replace(processor.tokenizer.pad_token, "")
    seq = re.sub(r"<.*?>", "", seq, count=1).strip()  # drop the leading task token

    confidence = _sequence_confidence(list(outputs.scores or []), outputs.sequences)
    return fields_from_cord(processor.token2json(seq), confidence=confidence)


def extract(image: Image.Image, read_vendor_and_date: bool = True, dayfirst: bool = False) -> ExtractedFields:
    """Full read of one page: amounts and rows from CORD, vendor and date from DocVQA.

    Set `read_vendor_and_date=False` to skip the two extra generations when only
    the money matters -- it roughly halves the time per page.
    """
    fields = parse_document(image)
    if not read_vendor_and_date:
        return fields

    from verity.extraction.document_qa import extract_field

    vendor = (extract_field(image, "vendor") or "").strip()
    fields.vendor = vendor or None
    raw_date = extract_field(image, "date")
    fields.date = parse_date(raw_date, dayfirst=dayfirst)
    fields.raw = {**fields.raw, "docvqa": {"vendor": vendor, "date": raw_date}}
    return fields
