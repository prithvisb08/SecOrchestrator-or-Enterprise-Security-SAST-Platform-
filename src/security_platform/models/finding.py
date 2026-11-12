import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from security_platform.enums.severity import Severity
from security_platform.enums.status import FindingStatus
from security_platform.models.location import SourceLocation
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class Finding(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    category: Category
    vulnerability_type: VulnerabilityType
    title: str
    description: str
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)

    location: SourceLocation
    code_snippet: str | None = None
    evidence: str | None = None
    root_cause: str | None = None
    attack_surface: str | None = None
    affected_component: str | None = None

    recommendation: str | None = None
    remediation_available: bool = False

    status: FindingStatus = FindingStatus.OPEN
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scanner_version: str
    metadata: dict[str, str] = Field(default_factory=dict)
    fingerprint: str = ""

    def get_fingerprint(self) -> str:
        """Returns stable fingerprint or computes fallback based on rule and location."""
        if self.fingerprint:
            return self.fingerprint
        if self.metadata and "fingerprint" in self.metadata:
            return self.metadata["fingerprint"]
        return f"{self.rule_id}:{self.location.file_path}:{self.location.start_line}"

    def transition_status(self, new_status: FindingStatus) -> None:
        """Handles state transitions for the finding."""
        # This can be expanded later with a proper state machine if needed.
        # For now, it enforces assignment validation via Pydantic.
        self.status = new_status
