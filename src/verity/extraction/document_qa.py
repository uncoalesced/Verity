"""Document QA with Donut -- OCR-free, reads the page image and its layout directly.

One model, one task. Swap models by changing MODEL_ID.
"""

from __future__ import annotations

import functools
import re

import torch
from PIL import Image
from transformers import DonutProcessor, VisionEncoderDecoderModel

MODEL_ID = "naver-clova-ix/donut-base-finetuned-docvqa"

# Zero-shot: the field name is turned into a natural question for the DocVQA head.
FIELD_QUESTIONS = {
    "vendor": "What is the name of the store?",
    "total": "What is the total amount?",
    "date": "What is the date?",
    "line_items": "What are the names of the items purchased?",
}


@functools.lru_cache(maxsize=1)
def _load() -> tuple[DonutProcessor, VisionEncoderDecoderModel, torch.device]:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    processor = DonutProcessor.from_pretrained(MODEL_ID)
    model = VisionEncoderDecoderModel.from_pretrained(MODEL_ID).to(device).eval()
    return processor, model, device


def extract_field(image: Image.Image, field: str, question: str | None = None) -> str:
    """Return the value Donut reads for `field`, or "" if it finds nothing."""
    processor, model, device = _load()
    prompt = question or FIELD_QUESTIONS.get(field, f"What is the {field}?")

    pixel_values = processor(image.convert("RGB"), return_tensors="pt").pixel_values.to(device)
    decoder_input_ids = processor.tokenizer(
        f"<s_docvqa><s_question>{prompt}</s_question><s_answer>",
        add_special_tokens=False,
        return_tensors="pt",
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
        )

    seq = processor.batch_decode(outputs)[0]
    seq = seq.replace(processor.tokenizer.eos_token, "").replace(processor.tokenizer.pad_token, "")
    seq = re.sub(r"<.*?>", "", seq, count=1).strip()  # drop the leading task token
    parsed = processor.token2json(seq)
    answer = parsed.get("answer", "") if isinstance(parsed, dict) else parsed
    return answer if isinstance(answer, str) else str(answer)
