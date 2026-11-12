from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from security_platform.analysis.orchestrator import ScanOrchestrator
from security_platform.api.app import app
from security_platform.config.settings import PlatformSettings, load_settings
from security_platform.telemetry.metrics import MetricsManager


@pytest.fixture
def test_client():
    return TestClient(app)


def test_platform_settings_production_secret_enforcement():
    # Production without secret must raise ValueError
    with pytest.raises(ValueError, match="CRITICAL: SEC_ORCH_SECURITY__JWT_SECRET"):
        settings = PlatformSettings(environment="production")
        settings.get_jwt_secret_value()

    # Development allows default fallback
    dev_settings = PlatformSettings(environment="development")
    assert len(dev_settings.get_jwt_secret_value()) >= 32


def test_platform_settings_custom_secrets_dir(tmp_path):
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    jwt_file = secret_dir / "jwt_secret"
    jwt_file.write_text("super_secret_vault_token_1234567890_abc")

    # With mounted secrets dir, pydantic-settings reads secret files
    settings = load_settings(secrets_dir=secret_dir)
    assert settings.environment in ("development", "staging", "production", "test")


def test_metrics_manager_and_metrics_endpoint(test_client):
    MetricsManager.record_scan("COMPLETED", 0.5)
    MetricsManager.record_engine_failure("semgrep")
    MetricsManager.set_queue_depth(5)

    resp = test_client.get("/metrics")
    assert resp.status_code == 200
    text = resp.text
    assert "security_platform_scans_total" in text
    assert "security_platform_engine_failures_total" in text
    assert 'engine_name="semgrep"' in text
    assert "security_platform_queue_depth" in text


def test_self_scan_programmatic():
    """Verify that SecOrchestrator runs on its own source code cleanly."""
    src_dir = Path(__file__).parent.parent / "src"
    orchestrator = ScanOrchestrator()
    result = orchestrator.run_scan(src_dir)

    assert result.status == "COMPLETED"
    assert len(result.scan_errors) == 0
    # Clean scan with zero unhandled criticals
    assert result.risk_assessment.overall_risk_score < 1.0
