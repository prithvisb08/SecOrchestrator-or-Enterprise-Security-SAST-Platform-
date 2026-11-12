import hashlib
import math
import re
import uuid
from collections import Counter

from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class SecretScanner:
    # Stable salt for reproducible finding deduplication hashes
    SECRET_SALT = "secorch_secret_salt_v1_"

    PATTERNS: dict[str, tuple[str, VulnerabilityType, Severity]] = {
        "AWS Access Key": (
            r"AKIA[0-9A-Z]{16}",
            VulnerabilityType.CLOUD_CREDENTIALS,
            Severity.CRITICAL,
        ),
        "Generic API Key": (
            r"(?i)(?:api[_-]?key|secret[_-]?key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,45})['\"]",
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
        "Slack Token": (
            r"xox[baprs]-[0-9a-zA-Z]{10,48}",
            VulnerabilityType.ACCESS_TOKEN,
            Severity.CRITICAL,
        ),
        "Google API Key": (
            r"AIza[0-9A-Za-z\-_]{35}",
            VulnerabilityType.API_KEY,
            Severity.HIGH,
        ),
        "Stripe Secret Key": (
            r"sk_live_[0-9a-zA-Z]{24,}",
            VulnerabilityType.API_KEY,
            Severity.CRITICAL,
        ),
        "Hardcoded Password": (
            r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{8,128})['\"]",
            VulnerabilityType.PASSWORD,
            Severity.HIGH,
        ),
        "Hardcoded Secret / Token": (
            r"(?i)(?:auth_token|access_token|client_secret|secret)\s*[:=]\s*['\"]([^'\"\s]{12,128})['\"]",
            VulnerabilityType.HARDCODED_SECRET,
            Severity.HIGH,
        ),
    }

    # Known dummy / placeholder values to ignore
    DUMMY_VALUES = {
        "password", "test", "dummy", "example", "changeme", "change_me",
        "secret", "none", "true", "false", "123456", "12345678", "admin", "root",
        "secorch_default_dev_secret_change_in_prod_minimum_32_bytes_long"
    }

    def __init__(self, scanner_version: str = "1.0.0"):
        self.scanner_version = scanner_version

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculates Shannon entropy in bits per character."""
        if not data:
            return 0.0
        length = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _extract_token_value(self, pattern: str, match: re.Match[str]) -> str:
        """Extracts the sensitive secret token rather than the surrounding key syntax."""
        if match.lastindex and match.lastindex >= 1:
            return match.group(match.lastindex)
        return match.group(0)

    def _redact_all_secrets_on_line(self, line: str) -> str:
        """Redacts all matched secret patterns anywhere on the line to prevent leakage."""
        redacted = line
        for _, (pattern, _, _) in self.PATTERNS.items():
            for m in re.finditer(pattern, line):
                token = self._extract_token_value(pattern, m)
                if token and token in redacted:
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
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue  # Skip pure comments

            line_findings: list[tuple[str, str, VulnerabilityType, Severity, str]] = []

            for name, (pattern, vuln_type, severity) in self.PATTERNS.items():
                for match in re.finditer(pattern, line):
                    token = self._extract_token_value(pattern, match)
                    if token.lower() in self.DUMMY_VALUES:
                        continue
                    # Ignore if assigned value matches variable name (e.g. ACCESS_TOKEN = "ACCESS_TOKEN")
                    var_match = re.search(r"([a-zA-Z0-9_]+)\s*[:=]", line)
                    if var_match and var_match.group(1).lower() == token.lower():
                        continue
                    token_hash = self._compute_salted_hash(token)
                    line_findings.append((name, pattern, vuln_type, severity, token_hash))

            if not line_findings:
                # Check for high-entropy assignment strings that might be unlabeled secrets
                assignment_match = re.search(r"['\"]([a-zA-Z0-9_\-+/=]{20,80})['\"]", line)
                if assignment_match:
                    raw_candidate = assignment_match.group(1)
                    # Ignore snake_case identifiers or metric names
                    if not ("_" in raw_candidate and raw_candidate.islower()):
                        if raw_candidate.lower() not in self.DUMMY_VALUES:
                            entropy = self.calculate_shannon_entropy(raw_candidate)
                            if entropy >= 3.8:
                                token_hash = self._compute_salted_hash(raw_candidate)
                                line_findings.append((
                                    "High-Entropy Secret Literal",
                                    "",
                                    VulnerabilityType.HARDCODED_SECRET,
                                    Severity.MEDIUM,
                                    token_hash
                                ))

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
