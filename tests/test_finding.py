from pathlib import Path

import pytest
from pydantic import ValidationError

from security_platform.enums.severity import Severity
from security_platform.enums.status import FindingStatus
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.models.repository import Repository
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


def test_finding_from_sample_json():
    sample_path = Path(__file__).resolve().parent / "examples" / "sample_finding.json"
    json_str = sample_path.read_text()
    finding = Finding.model_validate_json(json_str)

    assert finding.finding_id == "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    assert finding.rule_id == "SEC-SQL-001"
    assert finding.category == Category.SECURITY
    assert finding.vulnerability_type == VulnerabilityType.SQL_INJECTION
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == 0.96
    assert finding.location.file_path == "src/auth/login.py"
    assert finding.location.start_line == 84
    assert finding.status == FindingStatus.OPEN


def test_finding_defaults_and_validation():
    finding = Finding(
        rule_id="RULE-1",
        category=Category.QUALITY,
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        title="Test Title",
        description="Test Description",
        severity=Severity.HIGH,
        confidence=0.8,
        location=SourceLocation(file_path="app.py", start_line=10, end_line=12),
        scanner_version="1.0.0",
    )

    assert finding.finding_id is not None
    assert finding.status == FindingStatus.OPEN
    assert finding.discovered_at is not None

    finding.transition_status(FindingStatus.RESOLVED)
    assert finding.status == FindingStatus.RESOLVED


def test_confidence_validation():
    with pytest.raises(ValidationError):
        Finding(
            rule_id="RULE-1",
            category=Category.SECURITY,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            title="Invalid Confidence",
            description="Test",
            severity=Severity.LOW,
            confidence=1.5,
            location=SourceLocation(file_path="app.py", start_line=1, end_line=1),
            scanner_version="1.0.0",
        )

    with pytest.raises(ValidationError):
        Finding(
            rule_id="RULE-1",
            category=Category.SECURITY,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            title="Invalid Confidence",
            description="Test",
            severity=Severity.LOW,
            confidence=-0.1,
            location=SourceLocation(file_path="app.py", start_line=1, end_line=1),
            scanner_version="1.0.0",
        )


def test_invalid_severity():
    with pytest.raises(ValidationError):
        Finding(
            rule_id="RULE-1",
            category=Category.SECURITY,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            title="Invalid Severity",
            description="Test",
            severity="DOOMSDAY",  # type: ignore[arg-type]
            confidence=0.5,
            location=SourceLocation(file_path="app.py", start_line=1, end_line=1),
            scanner_version="1.0.0",
        )


def test_invalid_source_location():
    with pytest.raises(ValidationError):
        SourceLocation(file_path="test.py", start_line=10, end_line=5)


def test_finding_serialization_deserialization():
    finding = Finding(
        rule_id="SEC-SQL-001",
        category=Category.SECURITY,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        title="SQL Injection in Login",
        description="User input passed directly to database driver.",
        severity=Severity.CRITICAL,
        confidence=0.96,
        location=SourceLocation(file_path="src/auth/login.py", start_line=84, end_line=84),
        scanner_version="1.0.0",
    )
    json_data = finding.model_dump_json()
    loaded_finding = Finding.model_validate_json(json_data)
    assert loaded_finding.finding_id == finding.finding_id
    assert loaded_finding.category == finding.category
    assert loaded_finding.confidence == finding.confidence


def test_repository_model_creation():
    repo = Repository(
        repository_id="repo-42",
        repository_name="sample-project",
        source_type="local",
        scanner_version="1.0.0",
        branch="main",
        commit_hash="abc1234",
    )
    assert repo.repository_id == "repo-42"
    assert repo.source_type == "local"
    assert repo.scanned_at is not None
    assert repo.metadata == {}


