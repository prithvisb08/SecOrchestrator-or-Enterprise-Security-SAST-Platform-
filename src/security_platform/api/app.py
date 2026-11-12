import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from security_platform.analysis.orchestrator import ScanOrchestrator
from security_platform.api.auth import Role, UserContext, require_role
from security_platform.api.middleware import SecurityHeadersMiddleware
from security_platform.core.errors import ArchiveSecurityError
from security_platform.core.logging import logger
from security_platform.core.version import get_version
from security_platform.ingestion.loaders import ArchiveLoader
from security_platform.persistence.repository import scan_repository
from security_platform.reporting.exporter import ReportExporter

app = FastAPI(title="Enterprise Security Platform API", version=get_version())
app.add_middleware(SecurityHeadersMiddleware)

# Configured allow-listed roots for local scanning (preventing server filesystem traversal)
_DEFAULT_SCAN_ROOTS = [
    Path(tempfile.gettempdir()).resolve(),
]
if os.environ.get("SEC_ORCH_ALLOWED_SCAN_ROOT"):
    # secorch: ignore[SEC-TAINT-PATH_TRAVERSAL-001] reason="Admin configured scan root"
    _DEFAULT_SCAN_ROOTS.append(Path(os.environ["SEC_ORCH_ALLOWED_SCAN_ROOT"]).resolve())


def validate_scan_path(target_path_str: str) -> Path:
    """Validates that a requested local path is strictly contained within allowlisted roots."""
    try:
        resolved = Path(target_path_str).resolve()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid path format") from exc

    # Reject traversal characters or root directories explicitly
    if target_path_str.startswith(("/etc", "/proc", "/sys", "/root", "~")):
        raise HTTPException(
            status_code=400,
            detail="Forbidden target path: server filesystem scanning is restricted",
        )

    is_allowed = any(resolved.is_relative_to(root) for root in _DEFAULT_SCAN_ROOTS)
    if not is_allowed:
        raise HTTPException(
            status_code=400,
            detail="Forbidden target path: path must reside inside configured scan root",
        )

    if not resolved.exists():
        raise HTTPException(status_code=400, detail="Target path does not exist")

    return resolved


class ScanRequest(BaseModel):
    target_path: str = Field(..., description="Path within allowlisted scan root")
    asset_criticality: float = Field(1.0, ge=0.1, le=5.0, description="Asset criticality multiplier")


def run_scan_job(
    scan_id: str,
    tenant_id: str,
    target_path: Path,
    asset_criticality: float,
    cleanup_path: Path | None = None,
) -> None:
    try:
        orchestrator = ScanOrchestrator()
        result = orchestrator.run_scan(
            target_path,
            asset_criticality=asset_criticality,
            scan_id=scan_id,
        )

        exporter = ReportExporter()
        sarif_output = exporter.to_sarif(result.repository_id, result.findings)

        scan_repository.save(
            tenant_id=tenant_id,
            scan_id=scan_id,
            data={
                "status": result.status,
                "scan_id": scan_id,
                "tenant_id": tenant_id,
                "repository_id": result.repository_id,
                "findings_count": result.findings_count,
                "risk_assessment": result.risk_assessment.model_dump(mode="json"),
                "findings": [f.model_dump(mode="json") for f in result.findings],
                "scan_errors": [e.model_dump(mode="json") for e in result.scan_errors],
                "scanned_files_count": result.scanned_files_count,
                "duration_seconds": result.duration_seconds,
                "sarif": sarif_output,
            },
        )
    except Exception as exc:
        logger.exception("Scan job execution failed", extra={"scan_id": scan_id, "error": str(exc)})
        scan_repository.save(
            tenant_id=tenant_id,
            scan_id=scan_id,
            data={"status": "FAILED", "scan_id": scan_id, "error": str(exc)},
        )
    finally:
        if cleanup_path and cleanup_path.exists():
            shutil.rmtree(cleanup_path, ignore_errors=True)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Public healthcheck endpoint for load balancers and orchestrators."""
    return {"status": "healthy", "version": get_version()}


@app.post("/api/v1/scan")
def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: UserContext = Depends(require_role(Role.SCANNER)),
) -> dict[str, str]:
    """Initiates an asynchronous security scan on an allow-listed target path."""
    validated_path = validate_scan_path(request.target_path)
    scan_id = str(uuid.uuid4())

    scan_repository.save(
        tenant_id=current_user.tenant_id,
        scan_id=scan_id,
        data={"status": "RUNNING", "scan_id": scan_id, "tenant_id": current_user.tenant_id},
    )

    background_tasks.add_task(
        run_scan_job,
        scan_id,
        current_user.tenant_id,
        validated_path,
        request.asset_criticality,
    )
    return {"scan_id": scan_id, "status": "RUNNING"}


@app.post("/api/v1/scan/upload")
async def scan_archive_upload(
    background_tasks: BackgroundTasks,
    archive: UploadFile = File(...),
    asset_criticality: float = 1.0,
    current_user: UserContext = Depends(require_role(Role.SCANNER)),
) -> dict[str, str]:
    """Uploads and securely extracts a zip or tar repository archive for scanning."""
    scan_id = str(uuid.uuid4())
    raw_suffix = Path(archive.filename or "").suffix
    safe_suffix = raw_suffix if raw_suffix in {".zip", ".tar", ".gz", ".tgz"} else ".tmp"
    temp_archive = tempfile.NamedTemporaryFile(delete=False, suffix=safe_suffix)

    try:
        content = await archive.read()
        temp_archive.write(content)
        temp_archive.close()

        # Secure extraction using ArchiveLoader (enforces anti-zip-slip, anti-zip-bomb, no symlinks)
        workspace_dir = Path(tempfile.mkdtemp(prefix="secorch_scan_"))
        loader = ArchiveLoader(temp_archive.name, target_dir=workspace_dir)
        workspace = loader.get_workspace()
    except ArchiveSecurityError as exc:
        if os.path.exists(temp_archive.name):
            os.unlink(temp_archive.name)
        raise HTTPException(status_code=400, detail=f"Archive rejected: {exc.message}") from exc
    finally:
        if os.path.exists(temp_archive.name):
            os.unlink(temp_archive.name)

    scan_repository.save(
        tenant_id=current_user.tenant_id,
        scan_id=scan_id,
        data={"status": "RUNNING", "scan_id": scan_id, "tenant_id": current_user.tenant_id},
    )

    background_tasks.add_task(
        run_scan_job,
        scan_id,
        current_user.tenant_id,
        workspace,
        asset_criticality,
        cleanup_path=workspace,
    )

    return {"scan_id": scan_id, "status": "RUNNING"}


@app.get("/api/v1/scans/{scan_id}")
def get_scan_result(
    scan_id: str,
    current_user: UserContext = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Retrieves scan results scoped strictly to the authenticated tenant."""
    result = scan_repository.get(current_user.tenant_id, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return result


@app.get("/api/v1/scans/{scan_id}/sarif")
def get_scan_sarif(
    scan_id: str,
    current_user: UserContext = Depends(require_role(Role.VIEWER)),
) -> Response:
    """Retrieves SARIF 2.1.0 report for the given scan ID scoped to tenant."""
    result = scan_repository.get(current_user.tenant_id, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    if result.get("status") not in {"COMPLETED", "PARTIAL"}:
        raise HTTPException(status_code=400, detail="Scan is still in progress or failed")
    return Response(content=str(result["sarif"]), media_type="application/json")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    """Secure dashboard landing view."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Enterprise Security Orchestrator</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f8fafc; color: #0f172a; }
        .card { background: white; padding: 24px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; border: 1px solid #e2e8f0; }
        h1 { color: #0f172a; margin-bottom: 24px; }
    </style>
</head>
<body>
    <h1>Enterprise Security Orchestrator</h1>
    <div class="card">
        <h2>System Status: Active</h2>
        <p>API engine operational. Submit authenticated scans via <code>POST /api/v1/scan</code>.</p>
    </div>
</body>
</html>"""
