
from pydantic import BaseModel

from security_platform.enums.severity import Severity
from security_platform.risk.models import RiskAssessment


class GatePolicy(BaseModel):
    max_allowed_risk_score: float = 7.0
    fail_on_severities: list[Severity] = [Severity.CRITICAL]

class SecurityGateResult(BaseModel):
    passed: bool
    reasons: list[str]

class SecurityGateEvaluator:
    """Evaluates scan results against organizational security policies."""

    def __init__(self, policy: GatePolicy | None = None):
        self.policy = policy or GatePolicy()

    def evaluate(self, risk_assessment: RiskAssessment) -> SecurityGateResult:
        reasons = []

        # Check overall score threshold
        if risk_assessment.overall_risk_score > self.policy.max_allowed_risk_score:
            reasons.append(
                f"Overall risk score ({risk_assessment.overall_risk_score}) exceeds the limit ({self.policy.max_allowed_risk_score})."
            )

        # Check blocked severities
        for sev in self.policy.fail_on_severities:
            count = risk_assessment.risk_factors.get(sev.value, 0)
            if count > 0:
                reasons.append(f"Found {count} unresolved {sev.value} severity finding(s).")

        passed = len(reasons) == 0
        return SecurityGateResult(passed=passed, reasons=reasons)
