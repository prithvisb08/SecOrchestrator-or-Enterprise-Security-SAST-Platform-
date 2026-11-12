# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-12

### Added
- **Multi-Tenant Persistence:** PostgreSQL SQLAlchemy 2.x relational schema and tenant-isolated artifact storage for SARIF and SBOMs.
- **Asynchronous Execution:** Redis job queue and worker pool with HMAC-signed webhook dispatch.
- **Sandbox Runner:** Ephemeral container isolation (UID 65532, read-only rootfs, `--network=none`, drop `ALL` capabilities).
- **VCS Integrations:** GitHub App with Check Runs, inline line annotations, non-spamming in-place PR comment updating, and native SARIF upload; GitLab and Bitbucket adapters.
- **Automated Remediation:** Comment-preserving concrete syntax tree transformations via LibCST (`yaml.load` -> `yaml.safe_load`, hash upgrades, `shell=False`, parameterized SQL).
- **Alert Dispatchers:** Slack Block Kit, Microsoft Teams Connector cards, and Jira issue automation for Critical vulnerabilities.
- **Web UI & Dashboard:** React + TypeScript component models for project dashboards, scan history, interactive taint flow graph viewer, and triage workflows.
- **Production Observability:** Prometheus metrics (`scans_total`, `scan_duration_seconds`, `findings_by_engine`, `engine_failures_total`, `queue_depth`), OpenTelemetry tracing support, and structured JSON logs.
- **Kubernetes Helm Chart:** Hardened deployment, HPA, PodDisruptionBudget, Service, and NetworkPolicy templates.
- **Accurate Detection Quality:** Inter-procedural dataflow taint analysis, context-aware crypto suppression, and comprehensive framework source/sink rules.

### Security
- Hardened against Zip Slip, Zip Bomb, and symlink attacks in archive ingestion (`ArchiveLoader`).
- Implemented zero cleartext secret exposure with tenant-salted SHA-256 fingerprinting.
- Path traversal rejection across all API and CLI scan targets.
- Replaced average-based risk calculation with monotonic diminishing-gain model.
