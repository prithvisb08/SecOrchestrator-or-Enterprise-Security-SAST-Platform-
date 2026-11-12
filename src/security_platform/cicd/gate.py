import fnmatch

from pydantic import BaseModel, Field

from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.risk.models import RiskAssessment
from security_platform.taxonomy.categories import Category


class PolicyRule(BaseModel):
    name: str
    action: str = "BLOCK"  # "BLOCK" or "WARN"
    max_count: int = 0
    severity: Severity | None = None
    category: Category | None = None
    path_pattern: str | None = None  # e.g. "payments/*", "auth/*"
    only_new: bool = True  # Gating on new PR findings rather than legacy debt
    message: str = ""


class GatePolicy(BaseModel):
    name: str = "default_enterprise_gate"
    max_allowed_risk_score: float = 7.0
    fail_on_severities: list[Severity] = Field(default_factory=lambda: [Severity.CRITICAL])
    rules: list[PolicyRule] = Field(default_factory=list)


class SecurityGateResult(BaseModel):
    passed: bool
    reasons: list[str] = Field(default_factory=list)
    blocked_findings: list[Finding] = Field(default_factory=list)


class SecurityGateEvaluator:
    """Evaluates scan findings and risk metrics against policy-as-code guardrails."""

    def __init__(self, policy: GatePolicy | None = None):
        self.policy = policy or GatePolicy()

    def evaluate(
        self,
        risk_assessment: RiskAssessment,
        findings: list[Finding] | None = None
    ) -> SecurityGateResult:
        reasons: list[str] = []
        blocked: list[Finding] = []

        # 1. Overall risk score threshold
        if risk_assessment.overall_risk_score > self.policy.max_allowed_risk_score:
            reasons.append(
                f"Overall risk score ({risk_assessment.overall_risk_score}) exceeds threshold ({self.policy.max_allowed_risk_score})."
            )

        # 2. Base severity thresholds
        for sev in self.policy.fail_on_severities:
            count = risk_assessment.risk_factors.get(sev.value, 0)
            if count > 0:
                reasons.append(f"Found {count} unresolved {sev.value} severity finding(s).")

        # 3. Fine-grained policy rules
        if findings:
            for rule in self.policy.rules:
                matching_findings: list[Finding] = []
                for f in findings:
                    # Enforce PR diff rule: ignore legacy findings if only_new is set
                    if rule.only_new and f.metadata.get("lifecycle") not in {"NEW", None, ""}:
                        continue

                    # Filter by severity
                    if rule.severity and f.severity != rule.severity:
                        continue

                    # Filter by category
                    if rule.category and f.category != rule.category:
                        continue

                    # Filter by path pattern
                    if rule.path_pattern and not fnmatch.fnmatch(f.location.file_path, rule.path_pattern):
                        continue

                    matching_findings.append(f)

                if len(matching_findings) > rule.max_count:
                    detail = rule.message or f"found {len(matching_findings)} violations (max allowed: {rule.max_count})."
                    msg = f"Policy rule '{rule.name}': {detail}"
                    reasons.append(msg)
                    if rule.action.upper() == "BLOCK":
                        blocked.extend(matching_findings)

        passed = len(reasons) == 0
        return SecurityGateResult(
            passed=passed,
            reasons=reasons,
            blocked_findings=blocked
        )
