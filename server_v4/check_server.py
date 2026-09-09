"""Preflight checks for running VulDuet V4 on a Linux server."""

from __future__ import annotations

import importlib
import json
import platform
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = {
    "PrimeVul test set": ROOT / "data/test/primevul_test_paired.jsonl",
    "SVEN official 423 pairs": ROOT / "data/test/sven/sven_cpp_pairs_official_423.jsonl",
    "rule index": ROOT / "output/retrival/new_rule.index",
    "rule documents": ROOT / "output/step1/new_documents.json",
    "vulnerability index": ROOT / "output/retrival/vulnerability_knowledge_v3.index",
    "vulnerability documents": ROOT / "output/step1/vulnerability_knowledge_v3_documents.json",
    "public model configuration": ROOT / "src/config/config.yml",
    "private model configuration": ROOT / "src/config/config.local.yml",
}
MODULES = ("faiss", "FlagEmbedding", "numpy", "openai", "sklearn", "tqdm", "yaml")


def count_jsonl(path: Path) -> int:
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def main() -> int:
    print(f"Python: {sys.version.split()[0]}")
    print(f"Platform: {platform.platform()}")
    failures = []
    if sys.version_info < (3, 10):
        failures.append("Python 3.10 or newer is required")

    for name, path in REQUIRED_FILES.items():
        status = "OK" if path.is_file() else "MISSING"
        print(f"[{status}] {name}: {path.relative_to(ROOT)}")
        if not path.is_file():
            failures.append(f"missing {name}")

    for module in MODULES:
        try:
            importlib.import_module(module)
            print(f"[OK] Python module: {module}")
        except Exception as exc:
            print(f"[MISSING] Python module: {module} ({exc})")
            failures.append(f"missing module {module}")

    primevul = REQUIRED_FILES["PrimeVul test set"]
    sven = REQUIRED_FILES["SVEN official 423 pairs"]
    if primevul.is_file():
        lines = count_jsonl(primevul)
        print(f"PrimeVul records: {lines} (expected 870 functions / 435 pairs)")
        if lines != 870:
            failures.append(f"PrimeVul record count is {lines}, expected 870")
    if sven.is_file():
        pairs = count_jsonl(sven)
        print(f"SVEN pairs: {pairs} (expected 423)")
        if pairs != 423:
            failures.append(f"SVEN pair count is {pairs}, expected 423")

    local_config = REQUIRED_FILES["private model configuration"]
    if local_config.is_file():
        text = local_config.read_text(encoding="utf-8")
        if "replace-with-your-new-api-key" in text:
            failures.append("src/config/config.local.yml still contains the placeholder API key")
        else:
            print("[OK] Private API configuration exists (key value not displayed)")

    if failures:
        print("\nPreflight FAILED:")
        for item in failures:
            print(f"- {item}")
        return 1
    print("\nPreflight PASSED. V4 experiments are ready to run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
