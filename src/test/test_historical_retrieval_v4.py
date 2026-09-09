import json

from src.agent.historical_query_agent_v4 import HistoricalQueryAgentV4
from src.agent.vulnerability_reranker_v4 import VulnerabilityRerankerV4


class FakeLLM:
    def __init__(self, values):
        self.values = iter(values)

    def generate(self, _prompt):
        return json.dumps(next(self.values))


def candidate(number, similarity):
    return {
        "knowledge_id": f"VUL-{number}",
        "similarity": similarity,
        "cwe_ids": [],
        "functional_semantics": {"purpose": f"purpose {number}"},
        "vulnerability": {"abstract_cause": f"cause {number}"},
        "fix": {"strategy": f"fix {number}"},
    }


def test_historical_query_is_structured_and_label_free():
    value = {
        "functional_scenario": "parse a packet",
        "processed_objects": ["packet"],
        "external_inputs": ["buffer"],
        "security_sensitive_operations": ["length calculation"],
        "possible_failure_conditions": ["length mismatch"],
        "existing_protections": ["bounds check"],
    }
    result = HistoricalQueryAgentV4(FakeLLM([value])).analyze("code")
    assert result["status"] == "success"
    assert "Functional scenario: parse a packet" in result["query_text"]
    prompt = HistoricalQueryAgentV4.build_prompt("code")
    assert "Do not decide whether the function is vulnerable" in prompt


def test_reranker_selects_three_from_five_and_preserves_faiss_similarity():
    candidates = [candidate(i, 1 - i / 10) for i in range(1, 6)]
    rows = []
    # Reverse the FAISS preference: VUL-5 becomes the strongest reranked item.
    for i in range(1, 6):
        score = i / 5
        rows.append({
            "knowledge_id": f"VUL-{i}",
            "functional_match": score,
            "operation_match": score,
            "cause_relevance": score,
            "fix_relevance": score,
            "reason": "test",
        })
    reranker = VulnerabilityRerankerV4(
        FakeLLM([{"ranked_candidates": rows}]), reasoning_top_k=3
    )
    selected, ranked, diagnostics = reranker.select("query", candidates)
    assert [item["knowledge_id"] for item in selected] == ["VUL-5", "VUL-4", "VUL-3"]
    assert selected[0]["similarity"] == candidates[4]["similarity"]
    assert len(ranked) == 5 and diagnostics["status"] == "success"


def test_reranker_falls_back_to_faiss_order_after_invalid_responses():
    candidates = [candidate(i, 1 - i / 10) for i in range(1, 6)]
    invalid = {"ranked_candidates": []}
    reranker = VulnerabilityRerankerV4(
        FakeLLM([invalid, invalid, invalid]), reasoning_top_k=3
    )
    selected, _, diagnostics = reranker.select("query", candidates)
    assert [item["knowledge_id"] for item in selected] == ["VUL-1", "VUL-2", "VUL-3"]
    assert diagnostics["status"] == "fallback"


def test_negative_mismatch_scores_are_clamped_to_zero():
    candidates = [candidate(i, 1 - i / 10) for i in range(1, 4)]
    rows = [{
        "knowledge_id": f"VUL-{i}",
        "functional_match": -1,
        "operation_match": 0.5,
        "cause_relevance": 0.5,
        "fix_relevance": 0.5,
        "reason": "explicit mismatch",
    } for i in range(1, 4)]
    reranker = VulnerabilityRerankerV4(
        FakeLLM([{"ranked_candidates": rows}]), reasoning_top_k=2
    )
    _, ranked, diagnostics = reranker.select("query", candidates)
    assert diagnostics["status"] == "success"
    assert all(row["functional_match"] == 0.0 for row in ranked)
