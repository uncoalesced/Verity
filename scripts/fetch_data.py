"""Pull CORD into the local HF cache. Run once before the eval."""

from __future__ import annotations

import argparse

from datasets import load_dataset

from verity.eval.datasets import DATASET_ID, cache_dir


def main() -> None:
    ap = argparse.ArgumentParser(description="Download CORD into the local cache")
    ap.add_argument("--splits", nargs="+", default=["test"], choices=["train", "validation", "test"])
    args = ap.parse_args()

    target = cache_dir()
    target.mkdir(parents=True, exist_ok=True)
    for split in args.splits:
        ds = load_dataset(DATASET_ID, split=split, cache_dir=str(target))
        print(f"{DATASET_ID}:{split} -> {len(ds)} rows cached in {target}")


if __name__ == "__main__":
    main()
