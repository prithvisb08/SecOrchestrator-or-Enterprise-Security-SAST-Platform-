import json
from pathlib import Path

import pytest

from security_platform.engines.adapters.bandit import BanditEngine
from security_platform.engines.adapters.checkov import CheckovEngine
from security_platform.engines.adapters.gitleaks import GitleaksEngine
from security_platform.engines.adapters.osv import OSVScannerEngine
from security_platform.engines.adapters.semgrep import SemgrepEngine
from security_platform.engines.adapters.trivy import TrivyEngine
from security_platform.engines.base import Engine
from security_platform.engines.registry import EngineRegistry
from security_platform.enums.severity import Severity
from security_platform.ingestion.models import FileInventory, RepositorySnapshot
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


@pytest.fixture
def python_snapshot() -> RepositorySnapshot:
    return RepositorySnapshot(
        repository_id="test_repo",
        files=[
            FileInventory(file_path="app.py", size_bytes=100, sha256_hash="abc", language="python"),
            FileInventory(file_path="requirements.txt", size_bytes=50, sha256_hash="def", language="text"),
            FileInventory(file_path="Dockerfile", size_bytes=200, sha256_hash="ghi", language="dockerfile"),
        ]
    )


def test_bandit_parsing(tmp_path: Path):
    engine = BanditEngine()
    sample_json = json.dumps({
        "results": [
            {
                "test_id": "B602",
                "issue_text": "subprocess call with shell=True identified",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "filename": str(tmp_path / "app.py"),
                "line_number": 15,
                "code": "subprocess.run(cmd, shell=True)\n",
                "more_info": "https://bandit.readthedocs.io"
            },
            {
                "test_id": "B608",
                "issue_text": "Possible SQL injection vector through string-based query construction",
                "issue_severity": "MEDIUM",
                "issue_confidence": "MEDIUM",
                "filename": str(tmp_path / "db.py"),
                "line_number": 42,
                "code": "cursor.execute('SELECT * FROM ' + table)\n",
                "more_info": "https://bandit.readthedocs.io"
            }
        ]
    })

    findings = engine.parse_bandit_json(sample_json, tmp_path)
    assert len(findings) == 2
    assert findings[0].vulnerability_type == VulnerabilityType.COMMAND_INJECTION
    assert findings[0].severity == Severity.HIGH
    assert findings[0].location.file_path == "app.py"
    assert findings[1].vulnerability_type == VulnerabilityType.SQL_INJECTION
    assert findings[1].severity == Severity.MEDIUM


def test_semgrep_parsing(tmp_path: Path):
    engine = SemgrepEngine()
    sample_json = json.dumps({
        "results": [
            {
                "check_id": "python.flask.security.audit.xss.direct-use-of-jinja2",
                "path": str(tmp_path / "views.py"),
                "start": {"line": 10, "col": 5},
                "end": {"line": 10, "col": 35},
                "extra": {
                    "message": "Direct use of jinja2 template",
                    "severity": "ERROR",
                    "lines": "return Template(user_template).render()",
                    "metadata": {"cwe": ["CWE-79: Cross-site Scripting"]}
                }
            }
        ]
    })

    findings = engine.parse_semgrep_json(sample_json, tmp_path)
    assert len(findings) == 1
    assert findings[0].vulnerability_type == VulnerabilityType.CROSS_SITE_SCRIPTING
    assert findings[0].location.start_line == 10
    assert findings[0].location.start_column == 5


def test_gitleaks_parsing_and_redaction(tmp_path: Path):
    engine = GitleaksEngine()
    sample_json = json.dumps([
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": str(tmp_path / "secrets.env"),
            "StartLine": 5,
            "EndLine": 5,
            "Secret": "super_secret_raw_token_xyz_999",
            "Match": "API_KEY = \"super_secret_raw_token_xyz_999\""
        }
    ])

    findings = engine.parse_gitleaks_json(sample_json, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == Category.SECRETS
    # Zero tolerance for raw secrets in output/snippet
    assert "super_secret_raw_token_xyz_999" not in str(f.code_snippet)
    assert "[REDACTED_SECRET]" in str(f.code_snippet)
    assert "super_secret_raw_token_xyz_999" not in str(f.metadata)
    assert f.metadata["secret_hash"] != ""


def test_trivy_parsing(tmp_path: Path):
    engine = TrivyEngine()
    sample_json = json.dumps({
        "Results": [
            {
                "Target": str(tmp_path / "requirements.txt"),
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "CRITICAL",
                        "Title": "Proxy Authorization header leak"
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "AVD-DS-0001",
                        "Title": "Specify at least 1 USER command",
                        "Description": "Running containers as root grants high host privileges",
                        "Severity": "HIGH",
                        "IacMetadata": {"StartLine": 1}
                    }
                ]
            }
        ]
    })

    findings = engine.parse_trivy_json(sample_json, tmp_path)
    assert len(findings) == 2
    vuln_dep = next(f for f in findings if f.category == Category.DEPENDENCIES)
    assert vuln_dep.rule_id == "TRIVY-CVE-2023-32681"
    assert vuln_dep.severity == Severity.CRITICAL

    misconf = next(f for f in findings if f.category == Category.CONFIGURATION)
    assert misconf.rule_id == "TRIVY-AVD-DS-0001"
    assert misconf.severity == Severity.HIGH


def test_osv_scanner_parsing(tmp_path: Path):
    engine = OSVScannerEngine()
    sample_json = json.dumps({
        "results": [
            {
                "source": {"path": str(tmp_path / "package.json")},
                "packages": [
                    {
                        "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                        "vulnerabilities": [
                            {"id": "GHSA-jf85-cpcp-j695", "summary": "Prototype Pollution in lodash", "aliases": ["CVE-2020-8203"]}
                        ]
                    }
                ]
            }
        ]
    })

    findings = engine.parse_osv_json(sample_json, tmp_path)
    assert len(findings) == 1
    assert findings[0].category == Category.DEPENDENCIES
    assert "GHSA-jf85-cpcp-j695" in findings[0].title


def test_checkov_parsing(tmp_path: Path):
    engine = CheckovEngine()
    sample_json = json.dumps({
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_DOCKER_1",
                    "check_name": "Ensure container does not run as root",
                    "file_path": "/Dockerfile",
                    "file_line_range": [1, 2],
                    "severity": "HIGH",
                    "guideline": "Specify non-root USER instruction."
                }
            ]
        }
    })

    findings = engine.parse_checkov_json(sample_json, tmp_path)
    assert len(findings) == 1
    assert findings[0].vulnerability_type == VulnerabilityType.INSECURE_DOCKER
    assert findings[0].rule_id == "CHECKOV-CKV_DOCKER_1"


class MockCrashingEngine(Engine):
    @property
    def name(self) -> str:
        return "mock_crasher"

    @property
    def version(self) -> str:
        return "1.0.0"

    def is_available(self) -> bool:
        return True

    def supports(self, snapshot: RepositorySnapshot) -> bool:
        return True

    def run(self, workspace: Path, timeout_seconds: int = 60):
        raise RuntimeError("External tool crashed with segfault")


class MockWorkingEngine(Engine):
    @property
    def name(self) -> str:
        return "mock_worker"

    @property
    def version(self) -> str:
        return "1.0.0"

    def is_available(self) -> bool:
        return True

    def supports(self, snapshot: RepositorySnapshot) -> bool:
        return True

    def run(self, workspace: Path, timeout_seconds: int = 60):
        return [
            Finding(
                rule_id="MOCK-001",
                category=Category.SECURITY,
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                title="Mock Vulnerability",
                description="Mock finding",
                severity=Severity.HIGH,
                confidence=1.0,
                location=SourceLocation(file_path="app.py", start_line=1, end_line=1),
                scanner_version="1.0.0"
            )
        ]


def test_engine_registry_parallel_execution_and_partial_error(python_snapshot: RepositorySnapshot, tmp_path: Path):
    """
    Phase 4 requirement:
    Engines run in parallel. A failing engine marks the scan PARTIAL, not failed.
    """
    registry = EngineRegistry()
    registry.register(MockWorkingEngine())
    registry.register(MockCrashingEngine())

    findings, errors = registry.run_parallel(python_snapshot, tmp_path, max_workers=2)

    # Working engine's findings are collected
    assert len(findings) == 1
    assert findings[0].rule_id == "MOCK-001"

    # Failing engine's error is isolated and recorded, not bubbling up as an unhandled crash
    assert len(errors) == 1
    failed_engine_name, exc = errors[0]
    assert failed_engine_name == "mock_crasher"
    assert "segfault" in str(exc)
