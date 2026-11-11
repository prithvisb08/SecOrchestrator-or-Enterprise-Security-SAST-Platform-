from security_platform.engines.secret_scanner import SecretScanner
from security_platform.enums.severity import Severity
from security_platform.reporting.exporter import ReportExporter
from security_platform.risk.models import RiskAssessment


def test_secret_scanner_redacts_entire_secret_value():
    """True-Positive: Secret values must be fully redacted from snippets and evidence."""
    scanner = SecretScanner()
    raw_secret = "ghp_1234567890abcdefghijklmnopqrstuv"
    code = f'GITHUB_TOKEN = "{raw_secret}"\n'

    findings = scanner.scan_content("secrets.py", code)
    assert len(findings) == 1
    finding = findings[0]

    # Secret must NOT appear in snippet or evidence
    assert raw_secret not in (finding.code_snippet or "")
    assert raw_secret not in (finding.evidence or "")
    assert "[REDACTED_SECRET]" in (finding.code_snippet or "")

    # Salted hash / fingerprint exists
    assert hasattr(finding, "fingerprint") or "secret_hash" in finding.metadata or finding.finding_id is not None


def test_multiple_secrets_on_same_line_all_redacted():
    """True-Positive: If multiple secrets appear on one line, all must be redacted."""
    scanner = SecretScanner()
    sec1 = "AKIA1234567890ABCDEF"
    sec2 = "ghp_abcdefghijklmnopqrstuvwxyz123456"
    line = f'deploy(aws_key="{sec1}", gh_token="{sec2}")\n'

    findings = scanner.scan_content("deploy.py", line)
    assert len(findings) >= 1

    # Neither secret can appear in any finding snippet
    for f in findings:
        assert sec1 not in (f.code_snippet or "")
        assert sec2 not in (f.code_snippet or "")


def test_no_secret_in_json_or_sarif_reports():
    """Security verification: Assert that no raw secret ever leaks into JSON or SARIF export."""
    scanner = SecretScanner()
    raw_secret = "AKIAIOSFODNN7EXAMPLE"  # AWS documentation example
    code = f'aws_access_key_id = "{raw_secret}"\n'

    findings = scanner.scan_content("aws.py", code)
    assert len(findings) == 1

    exporter = ReportExporter()
    risk = RiskAssessment(
        repository_id="test-repo",
        overall_risk_score=8.0,
        risk_level=Severity.HIGH
    )

    # 1. Check JSON report
    json_report = exporter.to_json("test-repo", findings, risk)
    assert raw_secret not in json_report

    # 2. Check SARIF report
    sarif_report = exporter.to_sarif("test-repo", findings)
    assert raw_secret not in sarif_report
