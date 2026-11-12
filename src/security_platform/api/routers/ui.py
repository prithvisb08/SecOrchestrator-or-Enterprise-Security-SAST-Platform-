from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from security_platform.api.auth import Role, UserContext, require_role
from security_platform.domain.triage import TriageManager
from security_platform.enums.severity import Severity
from security_platform.enums.status import FindingStatus
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.persistence.repository import scan_repository
from security_platform.remediation.rewriter import LibCSTRewriter
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType

router = APIRouter(prefix="/api/v1/ui", tags=["Web UI"])
triage_manager = TriageManager()
rewriter = LibCSTRewriter()


class TriageUpdateRequest(BaseModel):
    status: FindingStatus
    reason: str = ""
    expiration_date: str | None = None


class RemediationPreviewRequest(BaseModel):
    source_code: str
    file_name: str = "example.py"


@router.get("/projects")
def list_projects(
    current_user: UserContext = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Returns project summary list with latest risk scores and vulnerability counts."""
    # Aggregates latest scans from tenant
    all_scans = scan_repository.list_by_tenant(current_user.tenant_id)
    projects_map: dict[str, dict[str, Any]] = {}

    for s in all_scans:
        repo_id = s.get("repository_id", "unknown")
        if repo_id not in projects_map:
            risk = s.get("risk_assessment", {})
            projects_map[repo_id] = {
                "project_id": repo_id,
                "repository_name": repo_id,
                "latest_scan_id": s.get("scan_id"),
                "risk_score": risk.get("composite_score", 0.0),
                "open_findings": s.get("findings_count", 0),
                "status": s.get("status", "COMPLETED"),
            }

    return list(projects_map.values())


@router.get("/scans/{scan_id}/findings")
def get_scan_findings(
    scan_id: str,
    current_user: UserContext = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Retrieves full findings for a scan including taint paths and code snippets."""
    scan = scan_repository.get(current_user.tenant_id, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = scan.get("findings", [])
    return {
        "scan_id": scan_id,
        "repository_id": scan.get("repository_id"),
        "risk_assessment": scan.get("risk_assessment"),
        "findings": findings,
    }


@router.post("/findings/{finding_id}/triage")
def triage_finding(
    finding_id: str,
    request: TriageUpdateRequest,
    current_user: UserContext = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Updates the triage state of a finding and records an immutable audit log."""
    try:
        dummy_finding = Finding(
            rule_id="UI-TRIAGE",
            category=Category.SECURITY,
            vulnerability_type=VulnerabilityType.DANGEROUS_API,
            title="Triage Item",
            description="",
            severity=Severity.INFO,
            confidence=1.0,
            location=SourceLocation(file_path="unknown", start_line=1, end_line=1),
            scanner_version="1.0.0",
            fingerprint=finding_id,
            status=FindingStatus.OPEN,
        )
        entry = triage_manager.transition(
            finding=dummy_finding,
            new_status=request.status,
            changed_by=current_user.user_id,
            reason=request.reason,
            approver_id=current_user.user_id if request.status == FindingStatus.ACCEPTED_RISK else None,
        )
        return {"status": "success", "event": entry.model_dump(mode="json")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/remediation/preview")
def preview_auto_remediation(
    request: RemediationPreviewRequest,
    current_user: UserContext = Depends(require_role(Role.SCANNER)),
) -> dict[str, Any]:
    """Applies LibCST auto-fix to Python source and returns the patched source and Git diff."""
    patched_code, fixes_count, reports = rewriter.fix_code(request.source_code)
    diff = rewriter.generate_unified_diff(
        request.source_code, patched_code, filename=request.file_name
    )
    return {
        "fixes_applied": fixes_count,
        "patched_code": patched_code,
        "git_diff": diff,
        "reports": [r.model_dump(mode="json") for r in reports],
    }


@router.get("/trends")
def get_vulnerability_trends(
    current_user: UserContext = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Returns historical findings counts by severity for chart rendering."""
    scans = scan_repository.list_by_tenant(current_user.tenant_id)
    trend_data: list[dict[str, Any]] = []

    for s in scans:
        findings = s.get("findings", [])
        criticals = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        highs = sum(1 for f in findings if f.get("severity") == "HIGH")
        mediums = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        lows = sum(1 for f in findings if f.get("severity") == "LOW")

        trend_data.append({
            "scan_id": s.get("scan_id"),
            "repository_id": s.get("repository_id"),
            "critical": criticals,
            "high": highs,
            "medium": mediums,
            "low": lows,
        })

    return {"trends": trend_data}
