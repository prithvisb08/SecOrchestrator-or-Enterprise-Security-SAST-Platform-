from fastapi.testclient import TestClient

from security_platform.api.app import app
from security_platform.api.telemetry_route import router
from security_platform.telemetry.metrics import MetricsManager

app.include_router(router)
client = TestClient(app)

def test_metrics_endpoint():
    # Record dummy metric data
    MetricsManager.record_scan(status="COMPLETED", duration=1.23)

    response = client.get("/metrics")
    assert response.status_code == 200
    assert "security_platform_scans_total" in response.text
    assert 'status="COMPLETED"' in response.text
