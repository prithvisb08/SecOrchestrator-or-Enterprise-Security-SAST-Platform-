
from security_platform.enums.severity import Severity
from security_platform.intelligence.context import AnalyzerContext
from security_platform.models.finding import Finding
from security_platform.models.rule import Rule as RuleMetadata
from security_platform.sast.core import DetectionRule, Evidence
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class UnsafeEvalExecRule(DetectionRule):
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-CODE-001",
            name="Unsafe Dynamic Code Execution",
            category=Category.SECURITY,
            vulnerability_type=VulnerabilityType.CODE_INJECTION,
            description="The use of eval() or exec() can allow attackers to execute arbitrary code if user input is passed to it.",
            default_severity=Severity.CRITICAL,
            references=["CWE-94"]
        )

    def analyze(self, context: AnalyzerContext) -> list[Finding]:
        findings = []
        dangerous_functions = {"eval", "exec"}
        for call in context.calls:
            if call.callee_name in dangerous_functions:
                evidence = Evidence(
                    location=call.location,
                    description=f"Direct call to dangerous built-in '{call.callee_name}' detected."
                )
                findings.append(self._create_finding(
                    evidence=evidence,
                    confidence=0.85,
                    root_cause=f"Application dynamically evaluates code using {call.callee_name}().",
                    recommendation="Avoid dynamic code execution. Use safer alternatives like ast.literal_eval() or structured configuration.",
                    scanner_version="1.0.0"
                ))
        return findings
