"""Leakage audit for historical-vulnerability knowledge sources."""

import hashlib
import re
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Set, Tuple


COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
TOKEN_RE = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
    r"[A-Za-z_]\w*|0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?|"
    r">>=|<<=|->|\+\+|--|==|!=|<=|>=|&&|\|\||<<|>>|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\S"
)
CODE_FIELDS = ("func", "code", "code_before_change", "code_after_change", "before_code", "after_code")


def record_id(record: Dict[str, Any], position: int) -> str:
    return str(record.get("idx") or record.get("id") or record.get("cve_id") or f"row-{position}")


def code_values(record: Dict[str, Any]) -> List[str]:
    values = []
    for field in CODE_FIELDS:
        value = record.get(field)
        if isinstance(value, str) and value.strip():
            values.append(value)
    for version in ("before", "after"):
        nested = record.get(version)
        if isinstance(nested, dict) and isinstance(nested.get("code"), str):
            values.append(nested["code"])
    return values


def normalized_code(code: str) -> str:
    return "".join(TOKEN_RE.findall(COMMENT_RE.sub("", code)))


def code_hash(code: str) -> str:
    return hashlib.sha256(normalized_code(code).encode("utf-8")).hexdigest()


def token_shingles(code: str, width: int = 5) -> Set[str]:
    tokens = TOKEN_RE.findall(COMMENT_RE.sub("", code))
    if not tokens:
        return set()
    if len(tokens) < width:
        return {hashlib.sha1("\x1f".join(tokens).encode()).hexdigest()[:16]}
    return {hashlib.sha1("\x1f".join(tokens[i:i + width]).encode()).hexdigest()[:16]
            for i in range(len(tokens) - width + 1)}


def _metadata_values(record: Dict[str, Any], names: Iterable[str]) -> Set[str]:
    output = set()
    for name in names:
        value = record.get(name)
        values = value if isinstance(value, list) else [value]
        output.update(str(x).strip().lower() for x in values if x is not None and str(x).strip())
    return output


def audit_records(train_records: List[Dict[str, Any]], test_records: List[Dict[str, Any]],
                  near_threshold: float = 0.85, max_bucket_size: int = 200) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Return clean training records and a raw-code-free audit report."""
    test_hashes = defaultdict(set); test_shingles = []; inverted = defaultdict(set)
    test_commits = defaultdict(set); test_cves = defaultdict(set)
    for pos, record in enumerate(test_records):
        rid = record_id(record, pos)
        for code in code_values(record):
            test_hashes[code_hash(code)].add(rid)
            index = len(test_shingles); shingles = token_shingles(code); test_shingles.append((rid, shingles))
            for shingle in shingles:
                inverted[shingle].add(index)
        for value in _metadata_values(record, ("commit_id", "commit")): test_commits[value].add(rid)
        for value in _metadata_values(record, ("cve_id", "cve", "CVE")): test_cves[value].add(rid)

    # Very common syntax shingles provide little identity information and create
    # huge candidate lists, so they are excluded from candidate generation.
    useful_inverted = {key: value for key, value in inverted.items() if len(value) <= max_bucket_size}
    clean = []; exclusions = []; seen_train_hashes = {}
    reason_counts = Counter()
    for pos, record in enumerate(train_records):
        rid = record_id(record, pos); reasons = []
        commits = _metadata_values(record, ("commit_id", "commit"))
        cves = _metadata_values(record, ("cve_id", "cve", "CVE"))
        for value in sorted(commits & set(test_commits)):
            reasons.append({"type": "commit_overlap", "value": value, "test_ids": sorted(test_commits[value])})
        for value in sorted(cves & set(test_cves)):
            reasons.append({"type": "cve_overlap", "value": value, "test_ids": sorted(test_cves[value])})
        for code in code_values(record):
            digest = code_hash(code)
            if digest in test_hashes:
                reasons.append({"type": "exact_code_overlap", "hash": digest, "test_ids": sorted(test_hashes[digest])})
                continue
            if digest in seen_train_hashes:
                reasons.append({"type": "duplicate_training_code", "hash": digest, "training_id": seen_train_hashes[digest]})
                continue
            shingles = token_shingles(code); candidates = Counter()
            for shingle in shingles:
                for index in useful_inverted.get(shingle, ()):
                    candidates[index] += 1
            for index, _shared in candidates.most_common():
                test_id, other = test_shingles[index]
                union = len(shingles | other)
                similarity = len(shingles & other) / union if union else 0.0
                if similarity >= near_threshold:
                    reasons.append({"type": "near_code_overlap", "similarity": round(similarity, 4), "test_ids": [test_id]})
                    break
        if reasons:
            unique = []
            for reason in reasons:
                if reason not in unique: unique.append(reason)
            for reason in unique: reason_counts[reason["type"]] += 1
            exclusions.append({"training_id": rid, "reasons": unique})
        else:
            clean.append(record)
            for code in code_values(record): seen_train_hashes[code_hash(code)] = rid
    report = {"audit_version": "v3", "configuration": {"near_duplicate_method": "C/C++ token 5-gram Jaccard",
              "near_duplicate_threshold": near_threshold, "max_inverted_bucket_size": max_bucket_size},
              "counts": {"training_records": len(train_records), "test_records": len(test_records),
              "accepted_records": len(clean), "excluded_records": len(exclusions), **dict(reason_counts)},
              "exclusions": exclusions}
    return clean, report
