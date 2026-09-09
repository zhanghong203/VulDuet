import json
import threading
import time
from types import SimpleNamespace

import pytest

from src.agent.arbiter_agent_v3 import ArbiterAgentV3
from src.agent.detector_dual_path_v3 import DualPathDetectorV3
from src.agent.vulnerability_reasoner_v3 import VulnerabilityReasonerV3
from src.util.dual_path_evidence_v3 import VulnerabilityEvidenceAggregatorV3, normalize_dual_path_evidence


class FakeLLM:
    def __init__(self, value): self.value = value
    def generate(self, _prompt): return json.dumps(self.value)


def knowledge():
    return {"knowledge_id": "VUL-1", "cwe_ids": ["CWE-401"], "functional_semantics": {},
            "vulnerability": {}, "fix": {}, "provenance": {"source_path": "train.json"}, "similarity": 0.8}


def reasoning(conclusion="Supports"):
    return {"knowledge_id": "VUL-1", "scenario_match": 0.9, "cause_present": "Yes",
            "trigger_present": "Yes", "fix_present": "No", "conclusion": conclusion,
            "confidence": 0.8, "evidence": {"cause_code": ["x"], "trigger_code": ["y"],
            "existing_fixes": [], "counter_evidence": []}, "analysis": "matched", "status": "success"}


def test_knowledge_reasoner_validates_structured_result():
    result = VulnerabilityReasonerV3(FakeLLM(reasoning())).reason("code", knowledge())
    assert result["status"] == "success" and result["confidence"] == 0.8


def test_knowledge_prompt_defines_applicability_independently_from_label():
    prompt = VulnerabilityReasonerV3(FakeLLM(reasoning())).build_prompt(
        "code", knowledge()
    )
    assert "patched implementation can still have a high scenario_match" in prompt
    assert "0.50-0.79" in prompt


def test_knowledge_reasoner_normalizes_signed_percentage_confidence():
    value = reasoning("Opposes")
    value["confidence"] = -95
    value["scenario_match"] = "80%"
    result = VulnerabilityReasonerV3(FakeLLM(value)).reason("code", knowledge())
    assert result["confidence"] == 0.95
    assert result["scenario_match"] == 0.8


def test_negative_scenario_match_becomes_inapplicable_not_failed():
    value = reasoning("Opposes")
    value["scenario_match"] = -0.9
    result = VulnerabilityReasonerV3(FakeLLM(value)).reason("code", knowledge())
    assert result["status"] == "success"
    assert result["scenario_match"] == 0.0


def test_knowledge_aggregation_and_normalization():
    summary = VulnerabilityEvidenceAggregatorV3().aggregate("desc", [knowledge()], [reasoning()])
    rule_summary = {"rule_results": [{"rule_id": "MEM31-C", "similarity": .7, "violation": "Yes",
        "confidence": .9, "weighted_score": .63, "eligible": True, "evidence": {}, "analysis": "leak"}]}
    unified = normalize_dual_path_evidence(rule_summary, summary)
    assert summary["path_decision"] == "vulnerable"
    assert {x["source_path"] for x in unified} == {"rule", "knowledge"}
    assert unified[1]["cwe_ids"] == ["CWE-401"]


def test_fixed_applicable_scenario_is_eligible_benign_evidence():
    fixed = reasoning("Opposes")
    fixed["scenario_match"] = 0.2
    fixed["cause_present"] = "No"
    fixed["trigger_present"] = "No"
    fixed["fix_present"] = "Yes"
    fixed["evidence"]["existing_fixes"] = ["added bounds guard"]
    summary = VulnerabilityEvidenceAggregatorV3().aggregate(
        "desc", [knowledge()], [fixed]
    )
    result = summary["knowledge_results"][0]
    assert result["eligible"] is True
    assert result["weighted_score"] < 0
    assert summary["path_decision"] == "benign"


def test_zero_match_fix_does_not_create_unrelated_benign_evidence():
    fixed = reasoning("Opposes")
    fixed["scenario_match"] = 0.0
    fixed["fix_present"] = "Yes"
    fixed["evidence"]["existing_fixes"] = ["unrelated guard"]
    summary = VulnerabilityEvidenceAggregatorV3().aggregate(
        "desc", [knowledge()], [fixed]
    )
    assert summary["knowledge_results"][0]["eligible"] is False
    assert summary["path_decision"] == "unknown"


def test_unknown_conclusion_never_becomes_eligible():
    unknown = reasoning("Unknown")
    summary = VulnerabilityEvidenceAggregatorV3().aggregate(
        "desc", [knowledge()], [unknown]
    )
    assert summary["knowledge_results"][0]["eligible"] is False
    assert summary["path_decision"] == "unknown"


def test_stronger_opposing_evidence_beats_weak_support():
    weak_item = knowledge()
    weak_item["knowledge_id"] = "VUL-WEAK"
    weak_item["similarity"] = 0.6
    strong_item = knowledge()
    strong_item["knowledge_id"] = "VUL-STRONG"
    strong_item["similarity"] = 0.9
    weak = reasoning("Supports")
    weak["knowledge_id"] = "VUL-WEAK"
    weak["scenario_match"] = 0.3
    weak["confidence"] = 0.6
    strong = reasoning("Opposes")
    strong["knowledge_id"] = "VUL-STRONG"
    strong["scenario_match"] = 0.9
    strong["confidence"] = 0.9
    summary = VulnerabilityEvidenceAggregatorV3().aggregate(
        "desc", [weak_item, strong_item], [weak, strong]
    )
    assert summary["path_decision"] == "benign"


def test_arbiter_rejects_invented_evidence():
    evidence = [{"source_path": "rule", "evidence_id": "MEM31-C", "claim": "supports_vulnerable",
                 "eligible": True, "cwe_ids": []}]
    bad = {"is_vulnerable": True, "confidence": .8, "decision_mode": "rule_only",
           "primary_evidence": [{"source_path": "rule", "evidence_id": "FAKE"}], "conflicts": [],
           "violated_rules": [], "related_cwes": [], "summary": "", "final_reason": ""}
    with pytest.raises(ValueError, match="invented"):
        ArbiterAgentV3(FakeLLM(bad))._validate(bad, evidence)


def test_arbiter_accepts_cross_path_grounded_decision():
    evidence = [{"source_path": "rule", "evidence_id": "MEM31-C", "claim": "supports_vulnerable", "eligible": True, "cwe_ids": []},
                {"source_path": "knowledge", "evidence_id": "VUL-1", "claim": "supports_vulnerable", "eligible": True, "cwe_ids": ["CWE-401"]}]
    good = {"is_vulnerable": True, "confidence": .9, "decision_mode": "cross_path_agreement",
            "primary_evidence": [{"source_path": "rule", "evidence_id": "MEM31-C"}, {"source_path": "knowledge", "evidence_id": "VUL-1"}],
            "conflicts": [], "violated_rules": ["MEM31-C"], "related_cwes": ["CWE-401"], "summary": "", "final_reason": ""}
    assert ArbiterAgentV3(FakeLLM(good))._validate(good, evidence)["is_vulnerable"]


def test_arbiter_derives_mode_instead_of_trusting_model_enum():
    evidence = [{"source_path": "rule", "evidence_id": "MEM31-C",
                 "claim": "supports_vulnerable", "eligible": True, "cwe_ids": []}]
    value = {"is_vulnerable": True, "confidence": .8,
             "decision_mode": "conflict_resolved",
             "primary_evidence": [{"source_path": "rule", "evidence_id": "MEM31-C"}],
             "conflicts": [], "violated_rules": ["MEM31-C"], "related_cwes": [],
             "summary": "", "final_reason": ""}
    result = ArbiterAgentV3(FakeLLM(value))._validate(value, evidence)
    assert result["decision_mode"] == "rule_only"


def test_same_path_opposition_is_not_labeled_cross_path_conflict():
    evidence = [
        {"source_path": "rule", "evidence_id": "R1", "claim": "supports_vulnerable", "eligible": True, "cwe_ids": []},
        {"source_path": "rule", "evidence_id": "R2", "claim": "supports_benign", "eligible": True, "cwe_ids": []},
    ]
    value = {"is_vulnerable": False, "confidence": .7, "decision_mode": "conflict_resolved",
             "primary_evidence": [{"source_path": "rule", "evidence_id": "R2"}],
             "conflicts": [], "violated_rules": [], "related_cwes": [], "summary": "", "final_reason": ""}
    result = ArbiterAgentV3(FakeLLM(value))._validate(value, evidence)
    assert result["decision_mode"] == "rule_only"
    assert result["conflicts"] == []


def test_dual_path_reasoning_runs_in_bounded_pool_and_preserves_order():
    class Reasoner:
        def reason(self, _code, item):
            time.sleep(0.02)
            return {"id": item["id"], "thread": threading.current_thread().name}

    detector = DualPathDetectorV3.__new__(DualPathDetectorV3)
    detector.reasoning_workers = 3
    detector.rule_path = SimpleNamespace(reasoner=Reasoner())
    detector.knowledge_reasoner = Reasoner()
    rules, knowledge_items = detector._reason_in_parallel(
        "code", [{"id": 1}, {"id": 2}], [{"id": 3}, {"id": 4}]
    )
    assert [item["id"] for item in rules] == [1, 2]
    assert [item["id"] for item in knowledge_items] == [3, 4]
    assert all(item["thread"].startswith("DualPathV3Reasoning")
               for item in rules + knowledge_items)
