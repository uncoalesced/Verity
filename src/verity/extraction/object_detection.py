"""Signature / stamp presence with YOLOS.

Optional for Month 1 -- the accuracy milestone does not depend on it -- but it
runs for real rather than returning a canned answer.
"""

from __future__ import annotations

import functools

import torch
from PIL import Image
from transformers import AutoImageProcessor, AutoModelForObjectDetection

MODEL_ID = "mdefrance/yolos-tiny-signature-detection"
THRESHOLD = 0.5


@functools.lru_cache(maxsize=1)
def _load():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    processor = AutoImageProcessor.from_pretrained(MODEL_ID)
    model = AutoModelForObjectDetection.from_pretrained(MODEL_ID).to(device).eval()
    return processor, model, device


def detect_signature(image: Image.Image, threshold: float = THRESHOLD) -> tuple[bool, float]:
    """Return (signature_present, best_score). Score is 0.0 when nothing clears `threshold`."""
    processor, model, device = _load()
    image = image.convert("RGB")

    inputs = processor(images=image, return_tensors="pt").to(device)
    with torch.no_grad():
        outputs = model(**inputs)

    results = processor.post_process_object_detection(
        outputs, threshold=threshold, target_sizes=torch.tensor([image.size[::-1]])
    )[0]
    scores = results["scores"]
    if len(scores) == 0:
        return False, 0.0
    return True, float(scores.max())
