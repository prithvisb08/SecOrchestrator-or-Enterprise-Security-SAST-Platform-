
from pydantic import BaseModel, Field

from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding


class AttackPathNode(BaseModel):
    step_number: int
    component: str
    description: str


class AttackPath(BaseModel):
    path_id: str
    title: str
    nodes: list[AttackPathNode] = Field(default_factory=list)


class CorrelatedFinding(BaseModel):
    correlation_id: str
    primary_finding: Finding
    correlated_findings: list[Finding] = Field(default_factory=list)
    merged_evidence: list[str] = Field(default_factory=list)
    attack_path: AttackPath | None = None


class RiskAssessment(BaseModel):
    repository_id: str
    overall_risk_score: float
    risk_level: Severity
    risk_factors: dict[str, float] = Field(default_factory=dict)
    explanations: list[str] = Field(default_factory=list)
