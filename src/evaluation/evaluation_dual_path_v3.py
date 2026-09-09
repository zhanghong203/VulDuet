"""Evaluate V3 final predictions, path ablations, agreement, and conflicts."""

import argparse
import json
from collections import Counter
from pathlib import Path

from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score, matthews_corrcoef, precision_score, recall_score


def _binary(decision):
    return 1 if decision == "vulnerable" else 0


def _metrics(labels, predictions):
    return {"accuracy": accuracy_score(labels, predictions),
            "balanced_accuracy": balanced_accuracy_score(labels, predictions),
            "precision": precision_score(labels, predictions, zero_division=0),
            "recall": recall_score(labels, predictions, zero_division=0),
            "f1": f1_score(labels, predictions, zero_division=0),
            "mcc": matthews_corrcoef(labels, predictions)}


def evaluate(path: Path):
    rows = json.loads(path.read_text(encoding="utf-8")); labels = []; final = []; rule = []; knowledge = []
    modes = Counter(); agreements = 0; conflicts = 0
    for row in rows:
        for version in ("before", "after"):
            result = row[version]; labels.append(int(row["labels"][version]))
            final.append(int(result["final_result"]["is_vulnerable"]))
            r = result["path_decisions"]["rule"]; k = result["path_decisions"]["knowledge"]
            rule.append(_binary(r)); knowledge.append(_binary(k)); modes[result["final_result"]["decision_mode"]] += 1
            agreements += r == k and r != "unknown"; conflicts += {r, k} == {"vulnerable", "benign"}
    n = len(labels)
    return {"result_path": str(path.resolve()), "pairs": len(rows), "functions": n,
            "final_metrics": _metrics(labels, final), "rule_path_metrics": _metrics(labels, rule),
            "knowledge_path_metrics": _metrics(labels, knowledge),
            "path_agreement_rate": agreements / n if n else 0.0,
            "path_conflict_rate": conflicts / n if n else 0.0, "arbiter_decision_modes": dict(modes)}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("result", type=Path); parser.add_argument("--save-json", type=Path)
    args = parser.parse_args(); metrics = evaluate(args.result); print(json.dumps(metrics, ensure_ascii=False, indent=2))
    if args.save_json:
        args.save_json.parent.mkdir(parents=True, exist_ok=True)
        args.save_json.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
