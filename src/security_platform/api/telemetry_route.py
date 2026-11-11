from fastapi import APIRouter, Response

from security_platform.telemetry.metrics import MetricsManager

router = APIRouter()

@router.get("/metrics")
def get_metrics() -> Response:
    """Prometheus metrics scraping endpoint."""
    return MetricsManager.metrics_response()
