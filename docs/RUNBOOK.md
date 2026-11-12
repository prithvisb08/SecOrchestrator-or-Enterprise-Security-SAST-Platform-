# SecOrchestrator Operational Runbook

## 1. Service Overview
SecOrchestrator is a cloud-native, multi-tenant enterprise SAST and security gate platform composed of:
- **API Server:** FastAPI application serving authenticated REST & GraphQL endpoints, webhooks, and dashboard.
- **Worker Pool:** Celery/Redis asynchronous workers executing sandboxed analysis engines.
- **Persistence Store:** PostgreSQL database storing tenants, scans, findings, policies, and audit logs.
- **Artifact Store:** Object storage (S3/MinIO) retaining SARIF, SBOMs, and engine logs.

## 2. Common Alerts & Remediation

### `HighQueueDepth` (Prometheus Alert: `security_platform_queue_depth > 50`)
- **Impact:** Scans take longer to complete; PR checks in CI/CD delayed.
- **Diagnosis:**
  ```bash
  kubectl get pods -n security-tools -l app=security-platform-worker
  kubectl top pods -n security-tools
  ```
- **Remediation:**
  Scale the worker deployment:
  ```bash
  kubectl scale deployment security-platform-worker --replicas=10 -n security-tools
  ```
  Check if HPA is hitting maximum replicas limit.

### `EngineExecutionFailures` (Prometheus Alert: `rate(security_platform_engine_failures_total[5m]) > 0.05`)
- **Impact:** Scans marked `PARTIAL` status; external engines (Semgrep, Trivy, Bandit) timing out.
- **Diagnosis:**
  Check worker logs for specific engine exceptions:
  ```bash
  kubectl logs -l app=security-platform-worker -n security-tools --tail=100 | grep "Engine"
  ```
- **Remediation:**
  Increase external engine subprocess timeout in `EngineConfig` or verify target repository file size.

### `DatabaseConnectionExhaustion`
- **Diagnosis:**
  Inspect SQLAlchemy connection pool usage:
  ```bash
  kubectl logs -l app=security-platform-api -n security-tools | grep "TimeoutError: QueuePool"
  ```
- **Remediation:**
  Increase `SEC_ORCH_DATABASE__POOL_SIZE` or tune PostgreSQL `max_connections`.

## 3. Disaster Recovery & Backups
- PostgreSQL automated daily snapshots with point-in-time recovery (PITR).
- S3 Artifact lifecycle policy: expire raw logs after 90 days, retain compliance SARIF / SBOMs for 365 days.
