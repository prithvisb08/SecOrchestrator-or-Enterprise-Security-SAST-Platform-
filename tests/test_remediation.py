from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.remediation.engine import RemediationEngine, RemediationResult
from security_platform.remediation.pr_creator import AutoPRCreator
from security_platform.remediation.rewriter import ASTRewriter
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


def test_ast_rewriter_upgrades_weak_hash():
    vulnerable_code = "import hashlib\ndef hash_pass(p):\n    return hashlib.md5(p.encode()).hexdigest()\n"
    rewriter = ASTRewriter()
    fixed_code, fixes_count = rewriter.fix_python_code(vulnerable_code)

    assert fixes_count == 1
    assert "hashlib.sha256" in fixed_code
    assert "hashlib.md5" not in fixed_code

def test_remediation_engine_applies_file_fix(tmp_path):
    code_file = tmp_path / "vulnerable.py"
    code_file.write_text("import hashlib\nh = hashlib.md5(b'test')")

    finding = Finding(
        rule_id="SEC-CRYPTO-001",
        category=Category.SECURITY,
        vulnerability_type=VulnerabilityType.INSECURE_CRYPTOGRAPHY,
        title="Weak Hash",
        description="Weak hash detected",
        severity=Severity.HIGH,
        confidence=0.9,
        location=SourceLocation(file_path="vulnerable.py", start_line=2, end_line=2),
        scanner_version="1.0"
    )

    engine = RemediationEngine()
    result = engine.apply_fixes_to_file(code_file, [finding])

    assert result is not None
    assert result.fixes_applied == 1
    assert "sha256" in code_file.read_text()

def test_auto_pr_creator_formatting():
    results = [
        RemediationResult(
            file_path="src/auth.py",
            fixes_applied=2,
            original_content="",
            patched_content=""
        )
    ]
    creator = AutoPRCreator()
    body = creator.format_pr_body(results)

    assert "2 security fix(es)" in body
    assert "`src/auth.py`" in body
