import re
import uuid

from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class SecretScanner:
    PATTERNS = {
        "AWS Access Key": (r"AKIA[0-9A-Z]{16}", VulnerabilityType.CLOUD_CREDENTIALS, Severity.CRITICAL),
        "Generic API Key": (r"(?i)(api[_-]?key|secret[_-]?key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,45})['\"]", VulnerabilityType.API_KEY, Severity.HIGH),
        "Private Key": (r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", VulnerabilityType.PRIVATE_KEY, Severity.CRITICAL),
        "GitHub Token": (r"ghp_[a-zA-Z0-9]{36}", VulnerabilityType.ACCESS_TOKEN, Severity.CRITICAL)
    }

    def __init__(self, scanner_version: str = "1.0.0"):
        self.scanner_version = scanner_version

    def scan_content(self, file_path: str, content: str, scanner_version: str | None = None) -> list[Finding]:
        version = scanner_version or self.scanner_version
        findings = []
        lines = content.splitlines()
        for line_idx, line in enumerate(lines, start=1):
            for name, (pattern, vuln_type, severity) in self.PATTERNS.items():
                match = re.search(pattern, line)
                if match:
                    redacted_snippet = re.sub(pattern, "[REDACTED_SECRET]", line)
                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        rule_id=f"SEC-SECRET-{vuln_type.upper()}-001",
                        category=Category.SECRETS,
                        vulnerability_type=vuln_type,
                        title=f"Hardcoded {name} Detected",
                        description=f"A potential {name} was found hardcoded in source code.",
                        severity=severity,
                        confidence=0.92,
                        location=SourceLocation(file_path=file_path, start_line=line_idx, end_line=line_idx),
                        code_snippet=redacted_snippet,
                        evidence=f"Matched pattern for {name} on line {line_idx}.",
                        root_cause="Storing credentials directly in source code exposes them to anyone with repository access.",
                        recommendation="Remove the secret immediately, revoke it, and use environment variables or a secure vault.",
                        scanner_version=version
                    )
                    findings.append(finding)
        return findings
