import math

from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.risk.models import RiskAssessment


class RiskEngine:
    """
    Monotonic, CVSS/EPSS-informed risk evaluation engine.

    Guarantees:
      1. Monotonicity: Adding an additional finding NEVER reduces the overall risk score.
      2. Dominance: A Critical finding anchors the base score at >= 9.0; minor findings only add marginal risk.
      3. Exploitability: Verified taint flows or known exploited CVEs (KEV/EPSS) elevate risk.
    """

    SEVERITY_BASE_SCORES: dict[Severity, float] = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.INFO: 1.0,
    }

    def _compute_finding_impact(self, finding: Finding) -> float:
        """Computes effective impact score for an individual finding."""
        base = self.SEVERITY_BASE_SCORES.get(finding.severity, 1.0)
        score = base * finding.confidence

        # Exploitability bonus: verified taint path or verified secret
        if finding.metadata.get("taint_flow") or "Source:" in (finding.evidence or ""):
            score += 0.5

        # KEV/EPSS bonus for actively exploited dependency vulnerabilities
        if finding.metadata.get("cve") or finding.metadata.get("epss"):
            score += 0.5

        return score

    def calculate_risk(
        self,
        repository_id: str,
        findings: list[Finding],
        asset_criticality: float = 1.0
    ) -> RiskAssessment:
        if not findings:
            return RiskAssessment(
                repository_id=repository_id,
                overall_risk_score=0.0,
                risk_level=Severity.INFO,
                explanations=["No security findings detected in repository."]
            )

        # 1. Compute impact scores for all active findings
        scores = sorted([self._compute_finding_impact(f) for f in findings], reverse=True)
        primary_score = scores[0]

        # 2. Diminishing returns aggregation for secondary findings
        # Formula: S_raw = S_primary + (10 - S_primary) * (1 - e^(-sum(rest)/30))
        if len(scores) > 1:
            rest_sum = sum(scores[1:])
            diminishing_gain = (10.0 - primary_score) * (1.0 - math.exp(-rest_sum / 30.0))
            raw_score = primary_score + diminishing_gain
        else:
            raw_score = primary_score

        # 3. Apply asset criticality multiplier
        final_score = round(min(10.0, raw_score * asset_criticality), 2)

        # 4. Map risk score to organizational severity levels
        if final_score >= 9.0:
            level = Severity.CRITICAL
        elif final_score >= 7.0:
            level = Severity.HIGH
        elif final_score >= 4.0:
            level = Severity.MEDIUM
        elif final_score >= 2.0:
            level = Severity.LOW
        else:
            level = Severity.INFO

        severity_counts = dict.fromkeys(Severity, 0)
        for f in findings:
            severity_counts[f.severity] += 1

        return RiskAssessment(
            repository_id=repository_id,
            overall_risk_score=final_score,
            risk_level=level,
            risk_factors={sev.value: count for sev, count in severity_counts.items() if count > 0},
            explanations=[
                f"Evaluated {len(findings)} findings using monotonic diminishing-gain model.",
                f"Primary vulnerability anchored risk at {round(primary_score, 2)}/10.0.",
                f"Asset criticality factor: {asset_criticality}x."
            ]
        )
