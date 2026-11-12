import json
from datetime import UTC, datetime, timedelta

import pytest

from security_platform.analysis.dedupe import FindingDeduplicator, compute_stable_fingerprint
from security_platform.cicd.gate import GatePolicy, PolicyRule, SecurityGateEvaluator
from security_platform.domain.triage import TriageManager
from security_platform.enums.severity import Severity
from security_platform.enums.status import FindingStatus
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.reporting.exporter import ReportExporter
from security_platform.risk.engine import RiskEngine
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


def _create_sample_finding(
    rule_id: str = "SEC-TEST-001",
    file_path: str = "src/app.py",
    line: int = 15,
    severity: Severity = Severity.HIGH,
    vuln_type: VulnerabilityType = VulnerabilityType.COMMAND_INJECTION,
    snippet: str = "os.system(cmd)",
    engine: str = "native"
) -> Finding:
    f = Finding(
        rule_id=rule_id,
        category=Category.SECURITY,
        vulnerability_type=vuln_type,
        title=f"Sample finding in {file_path}",
        description=f"Command injection detected on line {line}",
        severity=severity,
        confidence=0.90,
        location=SourceLocation(file_path=file_path, start_line=line, end_line=line, start_column=1, end_column=20),
        code_snippet=snippet,
        evidence=f"Engine {engine} flagged on line {line}.",
        root_cause="User input in command",
        recommendation="Use shlex.quote or parameterization.",
        scanner_version="1.0.0",
        metadata={"engine": engine}
    )
    f.fingerprint = compute_stable_fingerprint(f)
    return f


def test_cross_engine_deduplication():
    """
    Phase 5 Item 1: Stable fingerprints deduplicate findings across multiple engines.
    Native Dataflow, Bandit, and Semgrep all flagging the same line must merge into 1 finding.
    """
    f_native = _create_sample_finding(line=20, engine="native")
    f_bandit = _create_sample_finding(line=20, engine="bandit")
    f_semgrep = _create_sample_finding(line=20, engine="semgrep")

    # All three produce the same fingerprint
    assert f_native.fingerprint == f_bandit.fingerprint == f_semgrep.fingerprint

    deduped = FindingDeduplicator.deduplicate([f_native, f_bandit, f_semgrep])
    assert len(deduped) == 1
    primary = deduped[0]
    assert "bandit" in primary.metadata["engines"]
    assert "native" in primary.metadata["engines"]
    assert "semgrep" in primary.metadata["engines"]


def test_finding_lifecycle_transitions():
    """
    Phase 5 Item 1: Lifecycle tracking across scans (NEW, EXISTING, FIXED, REOPENED).
    """
    f1 = _create_sample_finding(line=10)
    f2 = _create_sample_finding(line=20)
    f3 = _create_sample_finding(line=30)

    # Scan 1: f1 and f2 detected for the first time
    curr1, fixed1 = FindingDeduplicator.compute_lifecycle(
        current_findings=[f1, f2],
        previous_findings=[]
    )
    assert len(curr1) == 2
    assert all(f.metadata["lifecycle"] == "NEW" for f in curr1)
    assert len(fixed1) == 0

    # Scan 2: f1 resolved, f2 still present (EXISTING), f3 newly detected (NEW)
    curr2, fixed2 = FindingDeduplicator.compute_lifecycle(
        current_findings=[f2, f3],
        previous_findings=curr1
    )
    assert len(curr2) == 2
    f2_res = next(f for f in curr2 if f.location.start_line == 20)
    f3_res = next(f for f in curr2 if f.location.start_line == 30)
    assert f2_res.metadata["lifecycle"] == "EXISTING"
    assert f3_res.metadata["lifecycle"] == "NEW"

    assert len(fixed2) == 1
    assert fixed2[0].location.start_line == 10
    assert fixed2[0].metadata["lifecycle"] == "FIXED"

    # Scan 3: f1 reappears! (REOPENED)
    curr3, _ = FindingDeduplicator.compute_lifecycle(
        current_findings=[f1],
        previous_findings=fixed2
    )
    assert len(curr3) == 1
    assert curr3[0].metadata["lifecycle"] == "REOPENED"
    assert curr3[0].status == FindingStatus.REOPENED


def test_triage_governance_and_audit_trail():
    """
    Phase 5 Item 2: Triage state machine and audit log.
    ACCEPTED_RISK requires a designated approver and rationale.
    """
    manager = TriageManager()
    finding = _create_sample_finding(line=15)

    # Transition to CONFIRMED
    entry1 = manager.transition(
        finding=finding,
        new_status=FindingStatus.CONFIRMED,
        changed_by="lead_sec_eng",
        reason="Verified active injection sink reachable from public route."
    )
    assert finding.status == FindingStatus.CONFIRMED
    assert entry1.previous_status == FindingStatus.OPEN

    # Transition to ACCEPTED_RISK without approver MUST fail
    with pytest.raises(ValueError, match="designated approver_id"):
        manager.transition(
            finding=finding,
            new_status=FindingStatus.ACCEPTED_RISK,
            changed_by="developer_alice",
            reason="Will fix in next quarter release."
        )

    # Valid transition to ACCEPTED_RISK with approver and expiry
    expiry = datetime.now(UTC) + timedelta(days=90)
    _entry2 = manager.transition(
        finding=finding,
        new_status=FindingStatus.ACCEPTED_RISK,
        changed_by="ciso_bob",
        approver_id="ciso_bob@enterprise.corp",
        expires_at=expiry,
        reason="Compensating WAF rule deployed; accepted until Q3 sprint."
    )
    assert finding.status == FindingStatus.ACCEPTED_RISK
    assert finding.metadata["risk_acceptance_approver"] == "ciso_bob@enterprise.corp"

    # Verify audit trail history
    audit_trail = manager.get_audit_trail_for_finding(finding.finding_id)
    assert len(audit_trail) == 2
    assert audit_trail[0].new_status == FindingStatus.CONFIRMED
    assert audit_trail[1].new_status == FindingStatus.ACCEPTED_RISK


def test_policy_as_code_pr_gating():
    """
    Phase 5 Item 4: Policy-as-code gate checks new findings in PR diff without failing on legacy debt.
    """
    legacy_finding = _create_sample_finding(line=5, severity=Severity.HIGH)
    legacy_finding.metadata["lifecycle"] = "EXISTING"

    new_critical = _create_sample_finding(line=15, severity=Severity.CRITICAL)
    new_critical.metadata["lifecycle"] = "NEW"

    payment_vuln = _create_sample_finding(file_path="payments/billing.py", line=40, severity=Severity.HIGH)
    payment_vuln.metadata["lifecycle"] = "NEW"

    risk_engine = RiskEngine()
    risk = risk_engine.calculate_risk("test_repo", [legacy_finding, new_critical, payment_vuln])

    policy = GatePolicy(
        max_allowed_risk_score=10.0,
        fail_on_severities=[],
        rules=[
            PolicyRule(
                name="Block New Criticals",
                severity=Severity.CRITICAL,
                only_new=True,
                max_count=0,
                message="No new CRITICAL findings permitted in pull requests."
            ),
            PolicyRule(
                name="Zero Tolerance for Payments Module",
                path_pattern="payments/*",
                only_new=True,
                max_count=0,
                message="Violations in payment flows are strictly prohibited."
            )
        ]
    )

    evaluator = SecurityGateEvaluator(policy)
    result = evaluator.evaluate(risk, findings=[legacy_finding, new_critical, payment_vuln])

    assert not result.passed
    assert len(result.reasons) == 2
    assert any("Block New Criticals" in r for r in result.reasons)
    assert any("Zero Tolerance for Payments Module" in r for r in result.reasons)
    # The legacy finding was ignored by the PR gate!
    assert legacy_finding not in result.blocked_findings


def test_complete_sarif_v210_spec():
    """
    Phase 5 Item 5 & A9: Complete SARIF 2.1.0 output validation.
    Checks partialFingerprints, security-severity, CWE tags, helpUri, and invocations.
    """
    finding = _create_sample_finding(
        rule_id="SEC-TAINT-SQL_INJECTION-001",
        file_path="src/database.py",
        line=42,
        severity=Severity.CRITICAL,
        vuln_type=VulnerabilityType.SQL_INJECTION,
        snippet="cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
    )
    finding.metadata["cwe"] = "CWE-89"

    exporter = ReportExporter()
    sarif_str = exporter.to_sarif(repository_id="enterprise-app", findings=[finding], scan_id="scan-12345")
    sarif = json.loads(sarif_str)

    # Schema & Version
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif

    # Runs & Tool Driver
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "SecOrchestrator"
    assert len(driver["rules"]) == 1

    rule = driver["rules"][0]
    assert rule["id"] == "SEC-TAINT-SQL_INJECTION-001"
    assert "https://cwe.mitre.org/data/definitions/89.html" in rule["helpUri"]
    assert rule["properties"]["security-severity"] == "9.5"
    assert "external/cwe/cwe-89" in rule["properties"]["tags"]

    # Invocation & Automation Details
    assert len(run["invocations"]) == 1
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["automationDetails"]["id"] == "secorch/enterprise-app/scan-12345"

    # Results
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["level"] == "error"

    # Partial fingerprints
    pf = res["partialFingerprints"]
    assert "primaryLocationLineHash" in pf
    assert "secorchFingerprint/v1" in pf
    assert pf["secorchFingerprint/v1"] != ""

    # Locations
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/database.py"
    region = loc["region"]
    assert region["startLine"] == 42
    assert region["startColumn"] == 1
    assert "cursor.execute" in region["snippet"]["text"]
