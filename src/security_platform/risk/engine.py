
from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.risk.models import RiskAssessment


class RiskEngine:
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.INFO: 1.0
    }

    def calculate_risk(self, repository_id: str, findings: list[Finding], asset_criticality: float = 1.0) -> RiskAssessment:
        if not findings:
            return RiskAssessment(
                repository_id=repository_id,
                overall_risk_score=0.0,
                risk_level=Severity.INFO,
                explanations=["No security findings detected."]
            )

        total_score = 0.0
        severity_counts = dict.fromkeys(Severity, 0)

        for finding in findings:
            severity_counts[finding.severity] += 1
            weight = self.SEVERITY_WEIGHTS.get(finding.severity, 1.0)
            total_score += weight * finding.confidence

        max_possible = len(findings) * 10.0
        normalized_score = round(min(10.0, (total_score / max_possible) * 10.0 * asset_criticality), 2)

        if normalized_score >= 8.0:
            level = Severity.CRITICAL
        elif normalized_score >= 6.0:
            level = Severity.HIGH
        elif normalized_score >= 4.0:
            level = Severity.MEDIUM
        elif normalized_score >= 2.0:
            level = Severity.LOW
        else:
            level = Severity.INFO

        return RiskAssessment(
            repository_id=repository_id,
            overall_risk_score=normalized_score,
            risk_level=level,
            risk_factors={sev.value: count for sev, count in severity_counts.items() if count > 0},
            explanations=[
                f"Evaluated {len(findings)} findings across code inventory.",
                "Critical/High finding counts factored into weighting.",
                f"Asset criticality multiplier applied: {asset_criticality}"
            ]
        )
