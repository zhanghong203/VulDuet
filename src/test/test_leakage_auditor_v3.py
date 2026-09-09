from src.util.leakage_auditor_v3 import audit_records, code_hash


def test_normalized_hash_ignores_comments_and_spacing():
    assert code_hash("int f(){ return 1; }") == code_hash("int f( ) { /* note */ return 1 ; }")


def test_audit_excludes_metadata_and_exact_code_overlap():
    testing = [{"idx": "t1", "commit_id": "abc", "cve_id": "CVE-1", "func": "int f(){return 1;}"}]
    training = [{"id": "commit", "commit_id": "ABC", "code_before_change": "void x(){}"},
                {"id": "cve", "cve_id": "cve-1", "code_before_change": "void y(){}"},
                {"id": "code", "code_before_change": "int f( ) { // same\n return 1; }"},
                {"id": "clean", "code_before_change": "int g(int x){return x + 7;}"}]
    clean, report = audit_records(training, testing)
    assert [row["id"] for row in clean] == ["clean"]
    assert report["counts"]["excluded_records"] == 3
    assert report["counts"]["commit_overlap"] == 1
    assert report["counts"]["cve_overlap"] == 1
    assert report["counts"]["exact_code_overlap"] == 1


def test_audit_excludes_near_duplicate():
    test_code = "int sum(int *a, int n){int s=0; for(int i=0;i<n;i++){s+=a[i];} return s;}"
    train_code = "int sum(int *a, int n){int s=0; for(int i=0;i<n;i++){s+=a[i];} return s+0;}"
    clean, report = audit_records([{"id": "near", "func": train_code}], [{"idx": "test", "func": test_code}], near_threshold=0.75)
    assert not clean
    assert report["counts"]["near_code_overlap"] == 1


def test_audit_removes_internal_training_duplicates():
    records = [{"id": "a", "func": "int z(){return 9;}"}, {"id": "b", "func": "int z( ){ return 9; }"}]
    clean, report = audit_records(records, [])
    assert [row["id"] for row in clean] == ["a"]
    assert report["counts"]["duplicate_training_code"] == 1
