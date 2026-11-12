import hmac
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from security_platform.analysis.orchestrator import ScanOrchestrator
from security_platform.persistence.artifacts import ArtifactStore
from security_platform.persistence.models import (
    Base,
    FindingRecord,
    Project,
    ScanRecord,
    Tenant,
    User,
)
from security_platform.workers.queue import ScanJob, ScanJobQueue
from security_platform.workers.sandbox import SandboxConfig, SandboxRunner
from security_platform.workers.worker import ScanWorker


@pytest.fixture
def test_db_engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return engine


def test_sqlalchemy_tenant_project_and_scan_models(test_db_engine):
    """
    Phase 6 Item 1: Multi-tenant relational schema with tenants, projects, scans, findings.
    """
    with Session(test_db_engine) as session:
        # Create Tenant
        tenant = Tenant(name="Acme Corp", plan="enterprise")
        session.add(tenant)
        session.commit()
        session.refresh(tenant)

        # Create User
        user = User(tenant_id=tenant.id, email="alice@acme.corp", role="admin")
        session.add(user)

        # Create Project
        project = Project(tenant_id=tenant.id, name="Payments Service", default_branch="main")
        session.add(project)
        session.commit()
        session.refresh(project)

        # Create Scan Record
        scan = ScanRecord(
            tenant_id=tenant.id,
            project_id=project.id,
            status="COMPLETED",
            scanner_version="1.0.0",
            findings_count=2,
            risk_score=7.5,
            risk_level="HIGH"
        )
        session.add(scan)

        # Create Finding Record
        finding = FindingRecord(
            tenant_id=tenant.id,
            project_id=project.id,
            fingerprint="secorch:v1:test_fp",
            rule_id="SEC-TAINT-SQL_INJECTION-001",
            title="SQL Injection",
            description="Untrusted user input in query",
            severity="HIGH",
            confidence=0.9,
            category="SECURITY",
            vulnerability_type="SQL_INJECTION",
            status="OPEN"
        )
        session.add(finding)
        session.commit()

        # Verify Querying
        stmt = select(Tenant).where(Tenant.name == "Acme Corp")
        queried_tenant = session.scalars(stmt).first()
        assert queried_tenant is not None
        assert len(queried_tenant.projects) == 1
        assert queried_tenant.projects[0].name == "Payments Service"
        assert len(queried_tenant.projects[0].scans) == 1


def test_job_queue_and_worker_with_webhook(tmp_path: Path):
    """
    Phase 6 Item 2: Distributed job queue, background worker processing, and signed webhooks.
    """
    queue = ScanJobQueue()
    worker = ScanWorker(job_queue=queue, webhook_secret="test_secret_123")

    code_file = tmp_path / "app.py"
    code_file.write_text("x = 1\n")

    job = ScanJob(
        scan_id="scan-abc",
        tenant_id="tenant-1",
        repository_id="test_repo",
        target_path=str(tmp_path),
        webhook_url="https://webhook.enterprise.corp/events"
    )
    queue.enqueue(job)
    assert queue.size() == 1

    with patch("httpx.Client.post") as mock_post:
        res = worker.process_one_available_job()
        assert res is not None
        assert res.scan_id == "scan-abc"
        assert res.status == "COMPLETED"

        # Webhook was called
        assert mock_post.called
        call_args = mock_post.call_args
        headers = call_args.kwargs["headers"]
        assert "X-SecOrch-Signature" in headers

        # Verify signature
        body = call_args.kwargs["content"]
        expected_sig = hmac.new(b"test_secret_123", body.encode("utf-8"), "sha256").hexdigest()
        assert headers["X-SecOrch-Signature"] == expected_sig


def test_sandbox_runner_security_configuration():
    """
    Phase 6 Item 3: Ephemeral container sandbox with Pod Security Restricted compliance.
    """
    config = SandboxConfig(
        memory_limit_mb=512,
        cpu_limit=1.5,
        read_only_rootfs=True,
        drop_all_capabilities=True,
        network_disabled=True,
        user="65532:65532"
    )
    runner = SandboxRunner(config)

    docker_cmd = runner.build_docker_run_command(
        image="ghcr.io/secorchestrator/scanner:latest",
        workspace_host_path="/tmp/target_repo",
        scan_command=["secorch", "scan", "/workspace"]
    )
    assert "--read-only" in docker_cmd
    assert "--network=none" in docker_cmd
    assert "--cap-drop=ALL" in docker_cmd
    assert "--user=65532:65532" in docker_cmd
    assert "/tmp/target_repo:/workspace:ro" in docker_cmd

    k8s_context = runner.build_k8s_security_context()
    assert k8s_context["runAsNonRoot"] is True
    assert k8s_context["readOnlyRootFilesystem"] is True
    assert k8s_context["allowPrivilegeEscalation"] is False
    assert k8s_context["capabilities"]["drop"] == ["ALL"]


def test_sha256_ast_caching_and_incremental_diff_scan(tmp_path: Path):
    """
    Phase 6 Item 4 & A4: Content SHA-256 caching avoids re-parsing unchanged files.
    Diff-only scanning scans only PR changed files.
    """
    orchestrator = ScanOrchestrator()

    file_a = tmp_path / "file_a.py"
    file_b = tmp_path / "file_b.py"
    file_a.write_text("import os; os.system('echo a')\n")
    file_b.write_text("import os; os.system('echo b')\n")

    # Initial scan: parses both files and caches them
    res1 = orchestrator.run_scan(tmp_path)
    assert res1.scanned_files_count == 2
    assert len(orchestrator._file_cache) == 2

    # Second scan with cache: files have identical sha256, hits cache
    with patch.object(orchestrator.dataflow_engine, "analyze_file") as mock_df:
        res2 = orchestrator.run_scan(tmp_path)
        # Should NOT call analyze_file because cache hit!
        assert mock_df.call_count == 0
        assert res2.findings_count == res1.findings_count

    # Incremental / diff-only scan: only scan file_a.py
    file_a.write_text("import os; os.system('echo updated_a')\n")  # modified file_a
    res_diff = orchestrator.run_scan(tmp_path, changed_files=["file_a.py"])
    assert res_diff.scanned_files_count == 1
    assert all(f.location.file_path == "file_a.py" for f in res_diff.findings)


def test_artifact_store_persistence_and_retention(tmp_path: Path):
    """
    Phase 6 Item 5: Artifact store with tenant isolation and retention policies.
    """
    store = ArtifactStore(base_storage_dir=tmp_path)

    sarif_content = '{"version": "2.1.0", "runs": []}'
    saved_path = store.save_artifact(
        tenant_id="tenant-alpha",
        scan_id="scan-99",
        filename="report.sarif",
        content=sarif_content,
        retention_days=30
    )
    assert saved_path.exists()

    loaded = store.load_artifact("tenant-alpha", "scan-99", "report.sarif")
    assert loaded is not None
    assert loaded.decode("utf-8") == sarif_content

    # Retention expiry: mock an expired artifact
    expired_path = store.save_artifact(
        tenant_id="tenant-alpha",
        scan_id="scan-old",
        filename="old.sbom.json",
        content="{}",
        retention_days=-1  # Expired yesterday
    )
    assert expired_path.exists()
    pruned = store.delete_expired_artifacts()
    assert pruned >= 1
    assert not expired_path.exists()
