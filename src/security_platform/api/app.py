import uuid
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from security_platform.analysis.orchestrator import ScanOrchestrator
from security_platform.core.version import get_version
from security_platform.reporting.exporter import ReportExporter

app = FastAPI(title="Enterprise Security Platform API", version=get_version())

# In-memory store for scan results
SCAN_RESULTS: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target_path: str = Field(..., description="Path to the repository to scan")
    asset_criticality: float = Field(1.0, ge=0.1, le=5.0, description="Asset criticality multiplier")


def run_scan_job(scan_id: str, target_path: str, asset_criticality: float) -> None:
    orchestrator = ScanOrchestrator()
    result = orchestrator.run_scan(
        target_path,
        asset_criticality=asset_criticality,
        scan_id=scan_id,
    )

    exporter = ReportExporter()
    sarif_output = exporter.to_sarif(result.repository_id, result.findings)

    SCAN_RESULTS[scan_id] = {
        "status": result.status,
        "repository_id": result.repository_id,
        "findings_count": result.findings_count,
        "risk_assessment": result.risk_assessment.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "scan_errors": [e.model_dump(mode="json") for e in result.scan_errors],
        "scanned_files_count": result.scanned_files_count,
        "duration_seconds": result.duration_seconds,
        "sarif": sarif_output,
    }


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy", "version": get_version()}


@app.post("/api/v1/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> dict[str, str]:
    scan_id = str(uuid.uuid4())
    SCAN_RESULTS[scan_id] = {"status": "RUNNING"}
    background_tasks.add_task(run_scan_job, scan_id, request.target_path, request.asset_criticality)
    return {"scan_id": scan_id, "status": "RUNNING"}


@app.get("/api/v1/scans/{scan_id}")
def get_scan_result(scan_id: str) -> dict[str, Any]:
    if scan_id not in SCAN_RESULTS:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return SCAN_RESULTS[scan_id]


@app.get("/api/v1/scans/{scan_id}/sarif")
def get_scan_sarif(scan_id: str) -> Response:
    if scan_id not in SCAN_RESULTS:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    result = SCAN_RESULTS[scan_id]
    if result.get("status") not in {"COMPLETED", "PARTIAL"}:
        raise HTTPException(status_code=400, detail="Scan is still in progress or failed")
    return Response(content=str(result["sarif"]), media_type="application/json")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Platform Dashboard</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f8fafc; color: #0f172a; }
            .card { background: white; padding: 24px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; border: 1px solid #e2e8f0; }
            h1 { color: #0f172a; margin-bottom: 24px; }
            .metric { font-size: 2rem; font-weight: bold; color: #2563eb; }
        </style>
    </head>
    <body>
        <h1>Enterprise Security Orchestrator</h1>
        <div class="card">
            <h2>System Status</h2>
            <p>API engine operational. Submit jobs via <code>POST /api/v1/scan</code>.</p>
        </div>
    </body>
    </html>
    """
