
import pytest

from security_platform.enums.severity import Severity
from security_platform.ingestion.models import FileInventory, RepositorySnapshot
from security_platform.intelligence.context import AnalyzerContext
from security_platform.sast.engine import SASTEngine
from security_platform.sast.rules.unsafe_execution import UnsafeEvalExecRule
from security_platform.sast.rules.weak_cryptography import WeakHashingRule
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


@pytest.fixture
def test_context(tmp_path):
    """Creates a mock AnalyzerContext with vulnerable code."""
    code = """
import hashlib
import json

def process_data(user_input):
    # Weak Crypto
    h = hashlib.md5(user_input.encode())

    # Unsafe Exec
    exec(user_input)

    # Safe alternatives (should not trigger false positives)
    safe_h = hashlib.sha256(user_input.encode())
    safe_parse = json.loads(user_input)

    return h.hexdigest()
"""
    code_file = tmp_path / "vulnerable.py"
    code_file.write_text(code)

    snapshot = RepositorySnapshot(
        repository_id="repo-test",
        scanner_version="1.0",
        files=[FileInventory(file_path="vulnerable.py", size_bytes=100, sha256_hash="hash", language="python")]
    )

    return AnalyzerContext(tmp_path, snapshot)

def test_sast_engine_detects_vulnerabilities(test_context):
    engine = SASTEngine()
    engine.register_rule(UnsafeEvalExecRule())
    engine.register_rule(WeakHashingRule())

    findings = engine.analyze_context(test_context)

    # We expect exactly 2 findings (MD5 and Exec)
    assert len(findings) == 2

    vuln_types = {f.vulnerability_type for f in findings}
    assert VulnerabilityType.CODE_INJECTION in vuln_types
    assert VulnerabilityType.INSECURE_CRYPTOGRAPHY in vuln_types

def test_unsafe_exec_rule_positive(test_context):
    rule = UnsafeEvalExecRule()
    findings = rule.analyze(test_context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.CRITICAL
    assert finding.rule_id == "SEC-CODE-001"
    assert "exec" in finding.evidence

def test_weak_crypto_rule_positive(test_context):
    rule = WeakHashingRule()
    findings = rule.analyze(test_context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.rule_id == "SEC-CRYPTO-001"
    assert "hashlib.md5" in finding.evidence

def test_sast_engine_no_false_positives(tmp_path):
    """Ensures safe usage doesn't trigger rules."""
    safe_code = """
import hashlib
import ast

def safe_process(user_input):
    safe_h = hashlib.sha256(user_input.encode())
    safe_val = ast.literal_eval(user_input)
    return safe_val
"""
    code_file = tmp_path / "safe.py"
    code_file.write_text(safe_code)

    snapshot = RepositorySnapshot(
        repository_id="repo-test",
        scanner_version="1.0",
        files=[FileInventory(file_path="safe.py", size_bytes=100, sha256_hash="hash", language="python")]
    )

    context = AnalyzerContext(tmp_path, snapshot)

    engine = SASTEngine([UnsafeEvalExecRule(), WeakHashingRule()])
    findings = engine.analyze_context(context)

    # Should be empty since we used sha256 and literal_eval
    assert len(findings) == 0
