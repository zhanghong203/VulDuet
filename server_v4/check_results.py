"""Validate V4 checkpoints after or during server execution."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "PrimeVul": (
        ROOT / "output/result/primevul/v4_historical_retrieval_single_blind_deepseek-v3.2_rulek5_vulretrieve5_vulreason3_smatch0p2_result.json",
        435,
    ),
    "SVEN": (
        ROOT / "output/result/sven/v4_historical_retrieval_sven_deepseek-v3.2_rulek5_vulretrieve5_vulreason3_smatch0p2_result.json",
        423,
    ),
}


def inspect(path: Path, expected: int) -> tuple[int, int, list[str]]:
    if not path.is_file():
        return 0, 0, ["result file missing"]
    rows = json.loads(path.read_text(encoding="utf-8"))
    ids = [str(row.get("id")) for row in rows]
    problems = []
    if len(ids) != len(set(ids)):
        problems.append(f"{len(ids) - len(set(ids))} duplicate IDs")
    incomplete = [
        str(row.get("id"))
        for row in rows
        if not (
            row.get("before", {}).get("final_result")
            and row.get("after", {}).get("final_result")
        )
    ]
    if incomplete:
        problems.append(f"{len(incomplete)} incomplete pairs")
    if len(set(ids)) > expected:
        problems.append(f"unique count exceeds expected total {expected}")
    return len(set(ids)), len(incomplete), problems


def main() -> int:
    failed = False
    for name, (path, expected) in TARGETS.items():
        unique, incomplete, problems = inspect(path, expected)
        remaining = max(expected - unique, 0)
        state = "COMPLETE" if unique == expected and not incomplete and not problems else "INCOMPLETE"
        print(f"{name}: {state}; unique={unique}/{expected}; remaining={remaining}; incomplete={incomplete}")
        for problem in problems:
            print(f"  - {problem}")
        failed |= state != "COMPLETE"
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
