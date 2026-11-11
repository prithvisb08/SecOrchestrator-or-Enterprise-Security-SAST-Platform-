import pytest

from security_platform.cicd.gate import GatePolicy, SecurityGateEvaluator
from security_platform.cicd.pr_commenter import PRCommenter
from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.risk.models import RiskAssessment
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


@pytest.fixture
def sample_risk_and_findings():
    risk = RiskAssessment(
        repository_id="test-repo",
        overall_risk_score=8.5,
        risk_level=Severity.CRITICAL,
        risk_factors={"CRITICAL": 1},
        explanations=["Critical vulnerability present."]
    )
    findings = [
        Finding(
            rule_id="SEC-CODE-001",
            category=Category.SECURITY,
            vulnerability_type=VulnerabilityType.CODE_INJECTION,
            title="Unsafe Exec",
            description="Dynamic code execution detected",
            severity=Severity.CRITICAL,
            confidence=0.9,
            location=SourceLocation(file_path="app.py", start_line=10, end_line=10),
            scanner_version="1.0"
        )
    ]
    return risk, findings

def test_security_gate_fails_on_critical(sample_risk_and_findings):
    risk, _ = sample_risk_and_findings
    evaluator = SecurityGateEvaluator(GatePolicy(max_allowed_risk_score=7.0))
    result = evaluator.evaluate(risk)

    assert result.passed is False
    assert len(result.reasons) == 2

def test_security_gate_passes_clean_scan():
    risk = RiskAssessment(
        repository_id="test-repo",
        overall_risk_score=1.0,
        risk_level=Severity.LOW,
        risk_factors={},
        explanations=[]
    )
    evaluator = SecurityGateEvaluator()
    result = evaluator.evaluate(risk)

    assert result.passed is True
    assert len(result.reasons) == 0

def test_pr_commenter_markdown_formatting(sample_risk_and_findings):
    risk, findings = sample_risk_and_findings
    evaluator = SecurityGateEvaluator()
    gate_result = evaluator.evaluate(risk)

    commenter = PRCommenter()
    markdown = commenter.format_markdown_comment(risk, findings, gate_result)

    assert "FAILED" in markdown
    assert "Unsafe Exec" in markdown
    assert "`app.py:10`" in markdown
