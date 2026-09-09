"""Run V4 historical-retrieval Rule-RAG + Vul-RAG on paired SVEN C/C++."""

import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice
from pathlib import Path

from src.agent.detector_dual_path_v4 import DualPathDetectorV4
from src.config.loader import load_llm_client
from src.util.result_saver_v2 import ResultSaverV2


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "data/test/sven/sven_cpp_pairs_official_423.jsonl"


def load_sven_pairs(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if "pair_id" not in row or "vulnerable" not in row or "patched" not in row:
                raise ValueError(f"Invalid SVEN pair at line {line_number}")
            yield row


def safe_tag(value: str) -> str:
    tag = "".join(
        character for character in value
        if character.isalnum() or character in {"-", "_"}
    )
    if not tag:
        raise ValueError("run tag must contain an alphanumeric character")
    return tag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--profile", default="deepseek_v3_2")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--reasoning-workers", type=int, default=5)
    parser.add_argument("--rule-top-k", type=int, default=5)
    parser.add_argument("--knowledge-retrieval-top-k", type=int, default=5)
    parser.add_argument("--knowledge-reasoning-top-k", type=int, default=3)
    parser.add_argument("--minimum-scenario-match", type=float, default=0.2)
    parser.add_argument("--minimum-confidence", type=float, default=0.5)
    parser.add_argument("--request-timeout", type=float, default=120)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--max-new", type=int)
    parser.add_argument("--run-tag")
    args = parser.parse_args()

    if min(
        args.workers,
        args.reasoning_workers,
        args.rule_top_k,
        args.knowledge_retrieval_top_k,
        args.knowledge_reasoning_top_k,
    ) < 1:
        parser.error("worker and top-k arguments must be at least 1")
    if args.knowledge_retrieval_top_k < args.knowledge_reasoning_top_k:
        parser.error("--knowledge-retrieval-top-k must be >= --knowledge-reasoning-top-k")
    if not 0 <= args.minimum_scenario_match <= 1:
        parser.error("--minimum-scenario-match must be between 0 and 1")
    if not 0 <= args.minimum_confidence <= 1:
        parser.error("--minimum-confidence must be between 0 and 1")
    if args.request_timeout <= 0:
        parser.error("--request-timeout must be greater than 0")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")
    if args.max_new is not None and args.max_new < 1:
        parser.error("--max-new must be at least 1")
    if not args.dataset.is_file():
        parser.error(f"SVEN dataset not found: {args.dataset}")

    llm = load_llm_client(args.profile)
    llm.client = llm.client.with_options(timeout=args.request_timeout, max_retries=0)
    detector = DualPathDetectorV4(
        llm,
        str(ROOT / "output/retrival/new_rule.index"),
        str(ROOT / "output/step1/new_documents.json"),
        str(ROOT / "output/retrival/vulnerability_knowledge_v3.index"),
        str(ROOT / "output/step1/vulnerability_knowledge_v3_documents.json"),
        rule_top_k=args.rule_top_k,
        knowledge_retrieval_top_k=args.knowledge_retrieval_top_k,
        knowledge_reasoning_top_k=args.knowledge_reasoning_top_k,
        minimum_confidence=args.minimum_confidence,
        minimum_scenario_match=args.minimum_scenario_match,
        reasoning_workers=args.reasoning_workers,
    )

    threshold_tag = str(args.minimum_scenario_match).replace(".", "p")
    name = (
        f"v4_historical_retrieval_sven_{llm.model}_rulek{args.rule_top_k}_"
        f"vulretrieve{args.knowledge_retrieval_top_k}_"
        f"vulreason{args.knowledge_reasoning_top_k}_smatch{threshold_tag}"
    )
    if args.limit:
        name += f"_smoke_{args.limit}"
    if args.run_tag:
        try:
            name += f"_{safe_tag(args.run_tag)}"
        except ValueError as exc:
            parser.error(str(exc))

    result_path = ROOT / "output/result/sven" / f"{name}_result.json"
    saver = ResultSaverV2(str(result_path), auto_save_every=1, resume=True)
    samples = load_sven_pairs(args.dataset)
    samples = islice(samples, args.limit) if args.limit else samples

    def run(sample):
        pair_id = sample["pair_id"]
        before = detector.detect(sample["vulnerable"]["code"], f"{pair_id}:vulnerable")
        after = detector.detect(sample["patched"]["code"], f"{pair_id}:patched")
        return {
            "id": pair_id,
            "cwe": sample.get("cwe", "Unknown"),
            "source_split": sample.get("source_split", ""),
            "func_name": sample.get("func_name", ""),
            "file_name": sample.get("file_name", ""),
            "commit_url": sample.get("commit_url", ""),
            "labels": {"before": 1, "after": 0},
            "model": llm.model,
            "experiment": "v4_historical_retrieval_sven",
            "configuration": {
                "rule_top_k": args.rule_top_k,
                "knowledge_retrieval_top_k": args.knowledge_retrieval_top_k,
                "knowledge_reasoning_top_k": args.knowledge_reasoning_top_k,
                "minimum_scenario_match": args.minimum_scenario_match,
                "minimum_confidence": args.minimum_confidence,
            },
            "before": before,
            "after": after,
        }

    pending = [sample for sample in samples if not saver.contains(sample["pair_id"])]
    if args.max_new is not None:
        pending = pending[:args.max_new]
    print(f"[SVEN V4] dataset={args.dataset}")
    print(f"[SVEN V4] output={result_path}")
    print(f"[SVEN V4] already_saved={len(saver.results)} pending={len(pending)}")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(run, sample): sample["pair_id"] for sample in pending}
        for future in as_completed(futures):
            pair_id = futures[future]
            try:
                saver.append(future.result())
                print(f"[Saved] {pair_id} ({len(saver.results)})")
            except Exception as exc:
                print(f"[Failed] {pair_id}: {exc}")
    saver.close()
    print(f"[SVEN V4] complete saved={len(saver.results)} output={result_path}")


if __name__ == "__main__":
    main()
