import uuid

from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class ConfigurationAnalyzer:
    def analyze_dockerfile(self, file_path: str, content: str, scanner_version: str = "1.0.0") -> list[Finding]:
        findings = []
        lines = content.splitlines()
        running_as_root = True

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip().upper()

            if stripped.startswith("USER "):
                user_val = stripped.split()[1]
                if user_val != "ROOT":
                    running_as_root = False

            if "DEBUG=TRUE" in stripped or "DEBUG=1" in stripped:
                findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    rule_id="SEC-CFG-DEBUG-001",
                    category=Category.CONFIGURATION,
                    vulnerability_type=VulnerabilityType.DEBUG_MODE,
                    title="Debug Mode Enabled in Container",
                    description="The container configuration has debug mode explicitly enabled.",
                    severity=Severity.MEDIUM,
                    confidence=0.95,
                    location=SourceLocation(file_path=file_path, start_line=line_idx, end_line=line_idx),
                    code_snippet=line,
                    evidence=f"Found debug flag on line {line_idx}.",
                    root_cause="Enabling debug mode in production containers can expose stack traces and internal service state.",
                    recommendation="Disable debug mode for production deployments.",
                    scanner_version=scanner_version
                ))

        if running_as_root:
            findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                rule_id="SEC-CFG-ROOT-001",
                category=Category.CONFIGURATION,
                vulnerability_type=VulnerabilityType.INSECURE_DOCKER,
                title="Container Runs as Root User",
                description="The Dockerfile does not switch to a non-privileged user, running processes as root by default.",
                severity=Severity.HIGH,
                confidence=0.90,
                location=SourceLocation(file_path=file_path, start_line=1, end_line=1),
                code_snippet="[File-level check]",
                evidence="No non-root USER instruction found in Dockerfile.",
                root_cause="Running containers as root grants unnecessary host system privileges if container isolation is breached.",
                recommendation="Add a dedicated non-root user via 'USER' instruction in the Dockerfile.",
                scanner_version=scanner_version
            ))

        return findings
