from security_platform.engines.config_analyzer import ConfigurationAnalyzer
from security_platform.engines.dependency_analyzer import DependencyAnalyzer
from security_platform.engines.secret_scanner import SecretScanner
from security_platform.enums.severity import Severity
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


def test_dependency_parser_requirements():
    content = "requests==2.31.0\n# comment\nflask>=2.2.0"
    analyzer = DependencyAnalyzer()
    deps = analyzer.analyze_manifest("requirements.txt", content)

    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].version == "2.31.0"

def test_secret_scanner_redaction():
    content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    scanner = SecretScanner()
    findings = scanner.scan_content("config.py", content)

    assert len(findings) == 1
    assert findings[0].vulnerability_type == VulnerabilityType.CLOUD_CREDENTIALS
    assert findings[0].severity == Severity.CRITICAL
    # Verify the actual secret value is redacted in the stored snippet
    assert "[REDACTED_SECRET]" in findings[0].code_snippet
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].code_snippet

def test_config_analyzer_dockerfile():
    content = """
FROM python:3.12
ENV DEBUG=TRUE
RUN pip install -r requirements.txt
"""
    analyzer = ConfigurationAnalyzer()
    findings = analyzer.analyze_dockerfile("Dockerfile", content)

    # Should detect both Debug Mode enabled and Running as Root
    assert len(findings) == 2
    vuln_types = {f.vulnerability_type for f in findings}
    assert VulnerabilityType.DEBUG_MODE in vuln_types
    assert VulnerabilityType.INSECURE_DOCKER in vuln_types
