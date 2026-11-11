from fastapi.testclient import TestClient

from security_platform.api.app import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_dashboard_endpoint():
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Enterprise Security Orchestrator" in response.text


def test_scan_flow(tmp_path):
    # Create sample repo to scan
    vulnerable_file = tmp_path / "app.py"
    vulnerable_file.write_text("import hashlib\nh = hashlib.md5(b'test')\n")

    response = client.post(
        "/api/v1/scan",
        json={"target_path": str(tmp_path), "asset_criticality": 1.0},
    )
    assert response.status_code == 200
    scan_id = response.json()["scan_id"]
    assert scan_id is not None

    # Wait for background task to finish (it runs synchronously in TestClient)
    res_response = client.get(f"/api/v1/scans/{scan_id}")
    assert res_response.status_code == 200
    res_data = res_response.json()
    assert res_data["status"] in {"COMPLETED", "PARTIAL"}
    assert res_data["findings_count"] >= 1

    # Verify SARIF export endpoint
    sarif_response = client.get(f"/api/v1/scans/{scan_id}/sarif")
    assert sarif_response.status_code == 200
    assert "application/json" in sarif_response.headers["content-type"]


def test_get_nonexistent_scan():
    response = client.get("/api/v1/scans/non-existent-id")
    assert response.status_code == 404
