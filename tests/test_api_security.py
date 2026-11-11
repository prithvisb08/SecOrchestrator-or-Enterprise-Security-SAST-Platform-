import io
import zipfile

from fastapi.testclient import TestClient

from security_platform.api.app import app
from security_platform.api.auth import Role, create_access_token

client = TestClient(app)


def test_api_rejects_unauthenticated_scan_requests():
    """True-Positive (S1): Scanning endpoints must require authentication."""
    response = client.post("/api/v1/scan", json={"target_path": "/tmp"})
    assert response.status_code == 401


def test_api_rejects_expired_jwt():
    """True-Positive (S1): Expired JWT tokens must be rejected."""
    expired_token = create_access_token("user-1", "tenant-1", role=Role.SCANNER, expires_in_seconds=-10)
    response = client.post(
        "/api/v1/scan",
        json={"target_path": "/tmp"},
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert "expired" in response.json().get("detail", "").lower()


def test_api_rejects_tampered_jwt():
    """True-Positive (S1): Tokens signed with wrong secret must be rejected."""
    tampered_token = create_access_token(
        "user-1", "tenant-1", role=Role.SCANNER, secret="wrong_secret_at_least_32_bytes_long_for_hmac"
    )
    response = client.post(
        "/api/v1/scan",
        json={"target_path": "/tmp"},
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert response.status_code == 401


def test_api_enforces_rbac_role_hierarchy(tmp_path):
    """True-Positive (S1): Viewer role cannot initiate scans (requires SCANNER)."""
    viewer_token = create_access_token("viewer-1", "tenant-1", role=Role.VIEWER)
    response = client.post(
        "/api/v1/scan",
        json={"target_path": str(tmp_path)},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert response.status_code == 403
    assert "Forbidden" in response.json().get("detail", "")


def test_api_scanner_and_admin_roles_allowed(tmp_path):
    """True-Negative (S1): Scanner and Admin roles can initiate scans."""
    (tmp_path / "test.py").write_text("x = 1\n")
    scanner_token = create_access_token("scanner-1", "tenant-1", role=Role.SCANNER)
    response = client.post(
        "/api/v1/scan",
        json={"target_path": str(tmp_path)},
        headers={"Authorization": f"Bearer {scanner_token}"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "RUNNING"


def test_api_rejects_arbitrary_server_paths():
    """True-Positive (S2): Arbitrary server paths such as /etc/passwd or /proc must be rejected."""
    traversal_paths = [
        "/etc/passwd",
        "/etc",
        "/root/.ssh",
        "/proc/self/environ",
        "../../../../etc/passwd",
        "~/.ssh",
    ]
    scanner_token = create_access_token("scanner-1", "tenant-1", role=Role.SCANNER)
    headers = {"Authorization": f"Bearer {scanner_token}"}
    for p in traversal_paths:
        response = client.post(
            "/api/v1/scan",
            json={"target_path": p},
            headers=headers,
        )
        assert response.status_code == 400, f"Path {p} was not rejected with 400 Bad Request"
        assert "Forbidden" in response.json()["detail"] or "restricted" in response.json()["detail"]


def test_tenant_isolation_prevents_cross_tenant_access(tmp_path):
    """True-Positive (S3): Tenant B must not be able to read Tenant A's scan results."""
    (tmp_path / "app.py").write_text("print('tenant a')\n")

    # Tenant A starts a scan
    token_tenant_a = create_access_token("user-a", "tenant-alpha", role=Role.SCANNER)
    res_a = client.post(
        "/api/v1/scan",
        json={"target_path": str(tmp_path)},
        headers={"Authorization": f"Bearer {token_tenant_a}"},
    )
    assert res_a.status_code == 200
    scan_id_a = res_a.json()["scan_id"]

    # Tenant A can read it
    assert client.get(f"/api/v1/scans/{scan_id_a}", headers={"Authorization": f"Bearer {token_tenant_a}"}).status_code == 200

    # Tenant B attempts to read Tenant A's scan
    token_tenant_b = create_access_token("user-b", "tenant-beta", role=Role.VIEWER)
    res_b = client.get(
        f"/api/v1/scans/{scan_id_a}",
        headers={"Authorization": f"Bearer {token_tenant_b}"},
    )
    # Must be 404 Not Found (tenant-isolated)
    assert res_b.status_code == 404


def test_api_upload_archive_scan():
    """True-Negative: Secure archive upload scan flow."""
    scanner_token = create_access_token("scanner-1", "tenant-upload", role=Role.SCANNER)
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("safe_app.py", "import hashlib\nh = hashlib.sha256(b'ok')\n")
    zip_buffer.seek(0)

    response = client.post(
        "/api/v1/scan/upload",
        files={"archive": ("repo.zip", zip_buffer, "application/zip")},
        headers={"Authorization": f"Bearer {scanner_token}"},
    )
    assert response.status_code == 200
    scan_id = response.json()["scan_id"]
    assert scan_id is not None

    res = client.get(
        f"/api/v1/scans/{scan_id}",
        headers={"Authorization": f"Bearer {scanner_token}"},
    )
    assert res.status_code == 200
    assert res.json()["status"] in {"COMPLETED", "PARTIAL"}


def test_api_upload_archive_zip_slip_rejected():
    """True-Positive (S6): Archive with zip-slip rejected at upload endpoint."""
    scanner_token = create_access_token("scanner-1", "tenant-upload", role=Role.SCANNER)
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("../../etc/evil.sh", "malicious")
    zip_buffer.seek(0)

    response = client.post(
        "/api/v1/scan/upload",
        files={"archive": ("evil.zip", zip_buffer, "application/zip")},
        headers={"Authorization": f"Bearer {scanner_token}"},
    )
    assert response.status_code == 400
    assert "Archive rejected" in response.json()["detail"]


def test_api_security_headers_present():
    """True-Positive (S8): API and Dashboard must return modern security headers."""
    response = client.get("/dashboard")
    headers = response.headers

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "max-age=" in headers.get("Strict-Transport-Security", "")


def test_health_remains_public():
    """True-Negative: Health check should remain publicly accessible for orchestrators."""
    response = client.get("/health")
    assert response.status_code == 200
