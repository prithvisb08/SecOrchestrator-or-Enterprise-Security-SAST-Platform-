from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.risk.engine import RiskEngine
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


def _make_finding(severity: Severity, confidence: float = 1.0) -> Finding:
    return Finding(
        rule_id="SEC-TEST-001",
        category=Category.SECURITY,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        title="Test Finding",
        description="A test security finding",
        severity=severity,
        confidence=confidence,
        location=SourceLocation(file_path="app.py", start_line=10, end_line=10),
        scanner_version="1.0.0",
    )


def test_empty_findings_risk():
    engine = RiskEngine()
    assessment = engine.calculate_risk("repo-1", [])
    assert assessment.overall_risk_score == 0.0
    assert assessment.risk_level == Severity.INFO
    assert len(assessment.explanations) > 0


def test_critical_finding_risk():
    engine = RiskEngine()
    findings = [_make_finding(Severity.CRITICAL, confidence=1.0)]
    assessment = engine.calculate_risk("repo-1", findings)
    assert assessment.overall_risk_score == 10.0
    assert assessment.risk_level == Severity.CRITICAL
    assert assessment.risk_factors.get("CRITICAL") == 1


def test_asset_criticality_scaling():
    engine = RiskEngine()
    findings = [_make_finding(Severity.MEDIUM, confidence=1.0)]
    # Default criticality 1.0 -> 5.0
    a1 = engine.calculate_risk("repo-1", findings, asset_criticality=1.0)
    assert a1.overall_risk_score == 5.0
    assert a1.risk_level == Severity.MEDIUM

    # Reduced criticality 0.5 -> 2.5
    a2 = engine.calculate_risk("repo-1", findings, asset_criticality=0.5)
    assert a2.overall_risk_score == 2.5
    assert a2.risk_level == Severity.LOW


def test_monotonic_risk_property():
    """
    A3 & Phase 5: Risk calculation must be strictly monotonic.
    Adding findings to a repository should never lower its risk score.
    """
    engine = RiskEngine()
    critical_only = [_make_finding(Severity.CRITICAL, confidence=1.0)]
    critical_plus_50_lows = [_make_finding(Severity.CRITICAL, confidence=1.0)] + [
        _make_finding(Severity.LOW, confidence=1.0) for _ in range(50)
    ]

    score_crit = engine.calculate_risk("repo-1", critical_only).overall_risk_score
    score_with_lows = engine.calculate_risk("repo-1", critical_plus_50_lows).overall_risk_score

    # Monotonicity check: score must not decrease when adding 50 vulnerabilities
    assert score_with_lows >= score_crit, f"Score decreased: {score_crit} -> {score_with_lows}"
    assert score_with_lows == 10.0

    # Adding lows to a Medium finding strictly increases risk
    medium_only = [_make_finding(Severity.MEDIUM, confidence=1.0)]
    medium_plus_lows = [_make_finding(Severity.MEDIUM, confidence=1.0)] + [
        _make_finding(Severity.LOW, confidence=1.0) for _ in range(10)
    ]
    score_med = engine.calculate_risk("repo-1", medium_only).overall_risk_score
    score_med_lows = engine.calculate_risk("repo-1", medium_plus_lows).overall_risk_score
    assert score_med_lows > score_med, "Adding findings failed to increase risk score"
