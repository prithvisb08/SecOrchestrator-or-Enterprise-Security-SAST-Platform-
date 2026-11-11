from abc import ABC, abstractmethod

from pydantic import BaseModel

from security_platform.intelligence.context import AnalyzerContext
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.models.rule import Rule as RuleMetadata


class Evidence(BaseModel):
    location: SourceLocation
    snippet: str | None = None
    description: str


class DetectionRule(ABC):
    @property
    @abstractmethod
    def metadata(self) -> RuleMetadata:
        pass

    @abstractmethod
    def analyze(self, context: AnalyzerContext) -> list[Finding]:
        pass

    def _create_finding(self, evidence: Evidence, confidence: float, root_cause: str, recommendation: str, scanner_version: str) -> Finding:
        return Finding(
            rule_id=self.metadata.rule_id,
            category=self.metadata.category,
            vulnerability_type=self.metadata.vulnerability_type,
            title=self.metadata.name,
            description=self.metadata.description,
            severity=self.metadata.default_severity,
            confidence=confidence,
            location=evidence.location,
            code_snippet=evidence.snippet,
            evidence=evidence.description,
            root_cause=root_cause,
            recommendation=recommendation,
            scanner_version=scanner_version
        )
