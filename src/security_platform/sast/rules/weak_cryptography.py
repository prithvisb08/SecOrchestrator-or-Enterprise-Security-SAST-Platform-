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
        weak_direct = {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}

        for call in context.calls:
            is_weak = False
            algo_name = call.callee_name

            if call.callee_name in weak_direct:
                is_weak = True
            elif call.callee_name == "hashlib.new" and call.args:
                first_arg = call.args[0].lower().strip("'\"")
                if first_arg in {"md5", "sha1"}:
                    is_weak = True
                    algo_name = f"hashlib.new('{first_arg}')"

            if not is_weak:
                continue

            used_for_sec = call.keywords.get("usedforsecurity", "").lower()
            if used_for_sec == "false":
                # Explicit non-security usage (e.g., cache checksum): downgrade to INFO
                severity = Severity.INFO
                confidence = 0.50
                title = f"Non-Security Hash Usage ({algo_name})"
                description = (
                    f"Usage of '{algo_name}' with usedforsecurity=False. Not used as a security primitive."
                )
            else:
                severity = Severity.HIGH
                confidence = 0.95
                title = f"Weak Cryptographic Hash Function ({algo_name})"
                description = (
                    f"Instantiation of weak hash algorithm '{algo_name}'. "
                    "MD5 and SHA-1 are vulnerable to collision attacks."
                )

            evidence = Evidence(
                location=call.location,
                description=description
            )
            finding = self._create_finding(
                evidence=evidence,
                confidence=confidence,
                root_cause=f"Application uses {algo_name} which is susceptible to collision attacks.",
                recommendation="Upgrade to a strong hashing algorithm such as SHA-256 or SHA-3.",
                scanner_version="1.0.0"
            )
            finding.severity = severity
            finding.title = title
            finding.description = description
            findings.append(finding)

        return findings
