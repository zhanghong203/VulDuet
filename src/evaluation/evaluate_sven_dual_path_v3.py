"""Evaluate paired SVEN V3 results and draw CWE-wise PairAcc bars."""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score


def _safe_div(numerator, denominator):
    return numerator / denominator if denominator else 0.0


def _final_prediction(detection):
    return int(bool(detection["final_result"]["is_vulnerable"]))


def _path_prediction(detection, path):
    decision = detection["path_decisions"][path]
    if decision == "vulnerable":
        return 1
    if decision == "benign":
        return 0
    return None


def _classification(labels, predictions):
    # Existing project evaluations conservatively map an unknown path decision
    # to non-vulnerable for function-level binary metrics.
    binary = [0 if value is None else value for value in predictions]
    tn = sum(y == 0 and p == 0 for y, p in zip(labels, binary))
    fp = sum(y == 0 and p == 1 for y, p in zip(labels, binary))
    return {
        "accuracy": accuracy_score(labels, binary),
        "precision": precision_score(labels, binary, zero_division=0),
        "recall": recall_score(labels, binary, zero_division=0),
        "f1": f1_score(labels, binary, zero_division=0),
        "fpr": _safe_div(fp, fp + tn),
    }


def _pair_correct(before, after):
    return before == 1 and after == 0


def evaluate(rows):
    labels = []
    predictions = {"rule": [], "knowledge": [], "final": []}
    grouped = defaultdict(lambda: {"pairs": 0, "rule": 0, "knowledge": 0, "final": 0})

    for row in rows:
        cwe = row.get("cwe") or "Unknown"
        before = {
            "rule": _path_prediction(row["before"], "rule"),
            "knowledge": _path_prediction(row["before"], "knowledge"),
            "final": _final_prediction(row["before"]),
        }
        after = {
            "rule": _path_prediction(row["after"], "rule"),
            "knowledge": _path_prediction(row["after"], "knowledge"),
            "final": _final_prediction(row["after"]),
        }
        labels.extend((1, 0))
        grouped[cwe]["pairs"] += 1
        for method in predictions:
            predictions[method].extend((before[method], after[method]))
            grouped[cwe][method] += int(_pair_correct(before[method], after[method]))

    total_pairs = len(rows)
    pair_accuracy = {
        method: _safe_div(sum(_pair_correct(values[i], values[i + 1]) for i in range(0, len(values), 2)), total_pairs)
        for method, values in predictions.items()
    }
    by_cwe = []
    for cwe in sorted(grouped):
        item = grouped[cwe]
        by_cwe.append({
            "cwe": cwe,
            "pairs": item["pairs"],
            "rule_pair_accuracy": _safe_div(item["rule"], item["pairs"]),
            "knowledge_pair_accuracy": _safe_div(item["knowledge"], item["pairs"]),
            "final_pair_accuracy": _safe_div(item["final"], item["pairs"]),
        })
    return {
        "pairs": total_pairs,
        "functions": total_pairs * 2,
        "pair_accuracy": pair_accuracy,
        "function_metrics": {
            method: _classification(labels, values) for method, values in predictions.items()
        },
        "by_cwe": by_cwe,
    }


def save_csv(metrics, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["cwe", "pairs", "rule_pair_accuracy", "knowledge_pair_accuracy", "final_pair_accuracy"]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(metrics["by_cwe"])


def plot(metrics, path):
    rows = list(metrics["by_cwe"])
    rows.append({
        "cwe": "Overall",
        "pairs": metrics["pairs"],
        "rule_pair_accuracy": metrics["pair_accuracy"]["rule"],
        "knowledge_pair_accuracy": metrics["pair_accuracy"]["knowledge"],
        "final_pair_accuracy": metrics["pair_accuracy"]["final"],
    })
    labels = [row["cwe"].replace("CWE-", "CWE-") for row in rows]
    x = np.arange(len(rows))
    width = 0.25
    series = [
        ("Rule-RAG", "rule_pair_accuracy", "#6f9bc3"),
        ("Vul-RAG", "knowledge_pair_accuracy", "#9fbe8f"),
        ("VulDuet", "final_pair_accuracy", "#d88782"),
    ]
    fig, ax = plt.subplots(figsize=(13, 5.8), dpi=180)
    for index, (name, key, color) in enumerate(series):
        values = [row[key] for row in rows]
        bars = ax.bar(x + (index - 1) * width, values, width, label=name, color=color,
                      edgecolor="#444444", linewidth=0.5)
        ax.bar_label(bars, labels=[f"{value:.2f}" for value in values], padding=2,
                     fontsize=7, rotation=90)
    ax.set_ylabel("Pair Accuracy")
    ax.set_xlabel("CWE Category")
    ax.set_title("SVEN CWE-wise Pair Accuracy")
    ax.set_xticks(x, labels, rotation=32, ha="right")
    ax.set_ylim(0, 1.10)
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.legend(loc="upper left", frameon=True)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("--output-prefix", type=Path)
    args = parser.parse_args()
    rows = json.loads(args.result.read_text(encoding="utf-8"))
    metrics = evaluate(rows)
    prefix = args.output_prefix or args.result.with_name(args.result.stem.replace("_result", "_metrics"))
    # Model names can contain dots (for example deepseek-v3.2), so with_suffix()
    # would incorrectly truncate part of the experiment name.
    json_path = Path(str(prefix) + ".json")
    csv_path = Path(str(prefix) + "_by_cwe.csv")
    image_path = Path(str(prefix) + "_pairacc_by_cwe.png")
    json_path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    save_csv(metrics, csv_path)
    plot(metrics, image_path)
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    print(f"metrics={json_path.resolve()}")
    print(f"by_cwe={csv_path.resolve()}")
    print(f"figure={image_path.resolve()}")


if __name__ == "__main__":
    main()
