
from security_platform.intelligence.context import AnalyzerContext
from security_platform.models.finding import Finding
from security_platform.sast.core import DetectionRule


class SASTEngine:
    def __init__(self, rules: list[DetectionRule] | None = None):
        self.rules = rules or []

    def register_rule(self, rule: DetectionRule) -> None:
        self.rules.append(rule)

    def analyze_context(self, context: AnalyzerContext) -> list[Finding]:
        all_findings = []
        for rule in self.rules:
            if rule.metadata.enabled:
                findings = rule.analyze(context)
                all_findings.extend(findings)
        return all_findings
