import hashlib
import re
import uuid

from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class SecretScanner:
    # Stable salt for reproducible finding deduplication hashes
    SECRET_SALT = "secorch_secret_salt_v1_"

    PATTERNS = {
        "AWS Access Key": (
            r"AKIA[0-9A-Z]{16}",
            VulnerabilityType.CLOUD_CREDENTIALS,
            Severity.CRITICAL,
        ),
        "Generic API Key": (
            r"(?i)(api[_-]?key|secret[_-]?key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,45})['\"]",
            VulnerabilityType.API_KEY,
            Severity.HIGH,
        ),
        "Private Key": (
            r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
            VulnerabilityType.PRIVATE_KEY,
            Severity.CRITICAL,
        ),
        "GitHub Token": (
            r"ghp_[a-zA-Z0-9]{30,40}",
            VulnerabilityType.ACCESS_TOKEN,
            Severity.CRITICAL,
        ),
    }

    def __init__(self, scanner_version: str = "1.0.0"):
        self.scanner_version = scanner_version

    def _extract_token_value(self, pattern: str, match: re.Match[str]) -> str:
        """Extracts the sensitive secret token rather than the surrounding key syntax."""
        if match.lastindex and match.lastindex >= 2:
            return match.group(2)
        return match.group(0)

    def _redact_all_secrets_on_line(self, line: str) -> str:
        """Redacts all matched secret patterns anywhere on the line to prevent leakage."""
        redacted = line
        for _, (pattern, _, _) in self.PATTERNS.items():
            for m in re.finditer(pattern, line):
                token = self._extract_token_value(pattern, m)
                if token:
                    redacted = redacted.replace(token, "[REDACTED_SECRET]")
        return redacted

    def _compute_salted_hash(self, secret_token: str) -> str:
        salted = f"{self.SECRET_SALT}{secret_token}"
        return hashlib.sha256(salted.encode("utf-8")).hexdigest()

    def scan_content(
        self, file_path: str, content: str, scanner_version: str | None = None
    ) -> list[Finding]:
        version = scanner_version or self.scanner_version
        findings: list[Finding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            line_findings: list[tuple[str, str, VulnerabilityType, Severity, str]] = []

            for name, (pattern, vuln_type, severity) in self.PATTERNS.items():
                for match in re.finditer(pattern, line):
                    token = self._extract_token_value(pattern, match)
                    token_hash = self._compute_salted_hash(token)
                    line_findings.append((name, pattern, vuln_type, severity, token_hash))

            if not line_findings:
                continue

            # Redact EVERY secret token on this line in one pass
            fully_redacted_snippet = self._redact_all_secrets_on_line(line)

            for name, _pattern, vuln_type, severity, token_hash in line_findings:
                fingerprint = f"rule:SEC-SECRET-{vuln_type.upper()}:hash:{token_hash[:16]}"
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
                    code_snippet=fully_redacted_snippet,
                    evidence=f"Matched pattern for {name} on line {line_idx} (fingerprint: {token_hash[:12]}).",
                    root_cause="Storing credentials directly in source code exposes them to anyone with repository access.",
                    recommendation="Remove the secret immediately, revoke it, and use environment variables or a secure vault.",
                    scanner_version=version,
                    metadata={"secret_hash": token_hash, "fingerprint": fingerprint},
                )
                findings.append(finding)

        return findings
