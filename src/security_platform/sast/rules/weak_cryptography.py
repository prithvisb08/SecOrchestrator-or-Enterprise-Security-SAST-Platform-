
from security_platform.enums.severity import Severity
from security_platform.intelligence.context import AnalyzerContext
from security_platform.models.finding import Finding
from security_platform.models.rule import Rule as RuleMetadata
from security_platform.sast.core import DetectionRule, Evidence
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class WeakHashingRule(DetectionRule):
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-CRYPTO-001",
            name="Weak Cryptographic Hash Function",
            category=Category.SECURITY,
            vulnerability_type=VulnerabilityType.INSECURE_CRYPTOGRAPHY,
            description="MD5 and SHA-1 are cryptographically broken and vulnerable to collision attacks.",
            default_severity=Severity.HIGH,
            references=["CWE-328"]
        )

    def analyze(self, context: AnalyzerContext) -> list[Finding]:
        findings = []
        weak_algorithms = {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}
        for call in context.calls:
            if call.callee_name in weak_algorithms:
                evidence = Evidence(
                    location=call.location,
                    description=f"Instantiation of weak hash algorithm '{call.callee_name}'."
                )
                findings.append(self._create_finding(
                    evidence=evidence,
                    confidence=0.95,
                    root_cause=f"The application uses {call.callee_name} which is susceptible to collision attacks.",
                    recommendation="Upgrade to a strong hashing algorithm such as SHA-256 or SHA-3.",
                    scanner_version="1.0.0"
                ))
        return findings
