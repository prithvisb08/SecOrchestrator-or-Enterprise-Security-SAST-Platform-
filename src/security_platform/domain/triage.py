import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from security_platform.enums.status import FindingStatus
from security_platform.models.finding import Finding


class TriageAuditEntry(BaseModel):
    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    previous_status: FindingStatus
    new_status: FindingStatus
    changed_by: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    reason: str
    approver_id: str | None = None
    expires_at: datetime | None = None


class TriageManager:
    """Manages finding triage lifecycle with validation and audit trail logging."""

    def __init__(self) -> None:
        self.audit_log: list[TriageAuditEntry] = []

    def transition(
        self,
        finding: Finding,
        new_status: FindingStatus,
        changed_by: str,
        reason: str,
        approver_id: str | None = None,
        expires_at: datetime | None = None,
    ) -> TriageAuditEntry:
        """
        Transitions a finding to a new triage status and records an immutable audit entry.
        Enforces governance: ACCEPTED_RISK requires a verified approver and rationale.
        """
        if new_status == FindingStatus.ACCEPTED_RISK:
            if not approver_id:
                raise ValueError("Transitioning to ACCEPTED_RISK requires a designated approver_id.")
            if not reason or len(reason.strip()) < 10:
                raise ValueError("Transitioning to ACCEPTED_RISK requires a detailed justification reason (>= 10 chars).")

        previous_status = finding.status
        finding.status = new_status

        if expires_at:
            finding.metadata["risk_acceptance_expires_at"] = expires_at.isoformat()
        if approver_id:
            finding.metadata["risk_acceptance_approver"] = approver_id

        entry = TriageAuditEntry(
            finding_id=finding.finding_id,
            previous_status=previous_status,
            new_status=new_status,
            changed_by=changed_by,
            reason=reason,
            approver_id=approver_id,
            expires_at=expires_at,
        )
        self.audit_log.append(entry)
        return entry

    def get_audit_trail_for_finding(self, finding_id: str) -> list[TriageAuditEntry]:
        return [e for e in self.audit_log if e.finding_id == finding_id]
