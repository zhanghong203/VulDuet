"""Run V4 PrimeVul evaluation with improved historical retrieval and V3 arbitration."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice
from pathlib import Path

from src.agent.detector_dual_path_v4 import DualPathDetectorV4
from src.config.loader import load_llm_client
from src.dataset.dataloader_v2 import PrimeVulPairLoaderV2
from src.util.result_saver_v2 import ResultSaverV2


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="deepseek_v3_2")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--run-tag",
        help="Optional result-name suffix for independent smoke-test runs.",
    )
    parser.add_argument("--reasoning-workers", type=int, default=5)
    parser.add_argument("--rule-top-k", type=int, default=5)
    parser.add_argument("--knowledge-retrieval-top-k", type=int, default=5)
    parser.add_argument("--knowledge-reasoning-top-k", type=int, default=3)
    parser.add_argument("--minimum-scenario-match", type=float, default=0.3)
    parser.add_argument("--minimum-confidence", type=float, default=0.5)
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=120,
        help="Maximum seconds for one API request; agent-level retries remain enabled.",
    )
    args = parser.parse_args()

    if min(args.workers, args.reasoning_workers, args.rule_top_k,
           args.knowledge_retrieval_top_k, args.knowledge_reasoning_top_k) < 1:
        parser.error("worker and top-k arguments must be at least 1")
    if args.knowledge_retrieval_top_k < args.knowledge_reasoning_top_k:
        parser.error("--knowledge-retrieval-top-k must be >= --knowledge-reasoning-top-k")
    if not 0 <= args.minimum_scenario_match <= 1:
        parser.error("--minimum-scenario-match must be between 0 and 1")
    if not 0 <= args.minimum_confidence <= 1:
        parser.error("--minimum-confidence must be between 0 and 1")
    if args.request_timeout <= 0:
        parser.error("--request-timeout must be greater than 0")

    llm = load_llm_client(args.profile)
    # The OpenAI SDK otherwise permits long transport-level waits and also adds
    # its own retries on top of each agent's three validated attempts. V4 keeps
    # retries at the agent layer so failures are observable and bounded.
    llm.client = llm.client.with_options(
        timeout=args.request_timeout,
        max_retries=0,
    )
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
        f"v4_historical_retrieval_single_blind_{llm.model}_rulek{args.rule_top_k}_"
        f"vulretrieve{args.knowledge_retrieval_top_k}_"
        f"vulreason{args.knowledge_reasoning_top_k}_smatch{threshold_tag}"
    )
    if args.limit:
        name += f"_smoke_{args.limit}"
    if args.run_tag:
        safe_tag = "".join(
            character for character in args.run_tag
            if character.isalnum() or character in {"-", "_"}
        )
        if not safe_tag:
            parser.error("--run-tag must contain an alphanumeric character")
        name += f"_{safe_tag}"
    saver = ResultSaverV2(
        str(ROOT / "output/result/primevul" / f"{name}_result.json"),
        auto_save_every=1,
        resume=True,
    )
    samples = PrimeVulPairLoaderV2(str(ROOT / "data/test/primevul_test_paired.jsonl"))
    samples = islice(samples, args.limit) if args.limit else samples

    def run(sample):
        before = detector.detect(sample["before"]["code"], f"{sample['id']}:function_1")
        after = detector.detect(sample["after"]["code"], f"{sample['id']}:function_2")
        return {
            "id": sample["id"],
            "commit_id": sample["commit_id"],
            "cwe": sample["cwe"],
            "labels": {
                "before": sample["before"]["label"],
                "after": sample["after"]["label"],
            },
            "model": llm.model,
            "experiment": "dual_path_single_blind_v4_historical_retrieval",
            "before": before,
            "after": after,
        }

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(run, sample): sample["id"]
            for sample in samples if not saver.contains(sample["id"])
        }
        for future in as_completed(futures):
            try:
                saver.append(future.result())
                print(f"[Saved] {futures[future]}")
            except Exception as exc:
                print(f"[Failed] {futures[future]}: {exc}")
    saver.close()


if __name__ == "__main__":
    main()
