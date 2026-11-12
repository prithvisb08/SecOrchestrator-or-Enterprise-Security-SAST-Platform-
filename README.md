# SecOrchestrator — Enterprise Security SAST Platform

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Coverage 85%](https://img.shields.io/badge/coverage-85%25-brightgreen.svg)](tests/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Security Hardened](https://img.shields.io/badge/hardened-UID%2065532%20%7C%20Non--Root-success.svg)](SECURITY.md)

SecOrchestrator is a production-grade, multi-tenant Static Application Security Testing (SAST) and security gate platform built with Python 3.12, FastAPI, Typer, SQLAlchemy 2.x, and LibCST. It unifies native inter-procedural taint analysis, secrets detection, and software supply chain analysis with orchestrated open-source scanners (Bandit, Semgrep, Gitleaks, Trivy, OSV-Scanner, Checkov).

---

## Key Capabilities

- **Unified Scan Pipeline:** A single `ScanOrchestrator` powering both high-throughput sandboxed workers and the developer-centric CLI (`secorch` / `sec-scan`).
- **Deep Taint & Dataflow Tracking:** Per-function taint scopes, parameter source tracking for Flask/Django/FastAPI route handlers, and sink-specific sanitizers (`shlex.quote` for shell, `int` for SQL).
- **Multi-Engine Orchestration:** Parallel execution of external tools (Semgrep, Bandit, Gitleaks, Trivy, OSV, Checkov) with isolated failure boundaries (scans marked `PARTIAL` on tool failure).
- **Deterministic Auto-Remediation:** Comment- and formatting-preserving concrete syntax tree transformations via LibCST (`yaml.load` → `yaml.safe_load`, weak hash upgrades, `shell=False`, parameterized SQL queries).
- **VCS Integrations:** GitHub App with Check Runs, inline line annotations, non-spamming in-place PR comment updating, and native SARIF upload; GitLab and Bitbucket adapters.
- **Monotonic Risk Engine:** Replaces flawed average-based models with a strictly monotonic diminishing-gain calculation ($\text{Risk}(S \cup \{f\}) \ge \text{Risk}(S)$) weighted by exploitability and asset criticality.
- **Security Supply Chain & Sandboxing:** Every scan runs in an ephemeral container (non-root UID 65532, read-only rootfs, `--network=none`, drop `ALL` capabilities).
- **Production Observability:** Prometheus metrics (`/metrics`), OpenTelemetry tracing support, and JSON structured logs.

---

## Architecture Overview

```
                      ┌───────────────────────────────────────┐
                      │    Developer / CI / GitHub Webhook    │
                      └───────────────────┬───────────────────┘
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │          SecOrchestrator API          │
                      │  - JWT & API Key RBAC Authentication  │
                      │  - Anti-Zip Slip / Anti-Bomb Loader   │
                      │  - Path Traversal Validation          │
                      └──────────────┬────────────────────────┘
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
    ┌───────────────────────────┐           ┌───────────────────────────┐
    │     Job Queue (Redis)     │           │   PostgreSQL Persistence  │
    └────────────┬──────────────┘           │   (Tenants, Findings,     │
                 │                          │    Triage, Policies)      │
                 ▼                          └───────────────────────────┘
    ┌───────────────────────────┐
    │  Ephemeral Worker Sandbox │
    │  - UID 65532 (Non-Root)   │
    │  - Read-Only Rootfs       │
    │  - Severed Network        │
    │  - Native Taint + Secrets │
    │  - Bandit / Semgrep /     │
    │    Gitleaks / Trivy / OSV │
    └────────────┬──────────────┘
                 │
                 ▼
    ┌───────────────────────────┐
    │ Reports & Auto-Remediation│
    │ - SARIF 2.1.0 & CycloneDX │
    │ - LibCST Git Patches & PR │
    │ - Slack / Teams / Jira    │
    └───────────────────────────┘
```

---

## Quick Start

### Installation

```bash
git clone https://github.com/secorchestrator/secorchestrator.git
cd secorchestrator

# Install dependencies using uv
uv sync --extra dev
```

### CLI Usage

```bash
# Scan a directory with rich terminal output
uv run secorch scan ./src

# Export full OASIS SARIF 2.1.0 report
uv run secorch scan ./src --format sarif > results.sarif

# Export CycloneDX 1.5 JSON SBOM
uv run secorch scan ./src --format cyclonedx > sbom.json

# Apply automated LibCST security fixes
uv run secorch remediate ./src
```

### Running the API & Workers

```bash
# Start the API server
uv run uvicorn security_platform.api.app:app --host 0.0.0.0 --port 8000

# Access OpenAPI documentation
open http://localhost:8000/docs

# Scrape Prometheus metrics
curl http://localhost:8000/metrics
```

### Kubernetes Deployment (Helm)

```bash
helm install secorchestrator deployments/k8s/helm/ \
  --namespace security-tools \
  --create-namespace \
  --set image.tag="1.0.0"
```

---

## Verification & Test Suite

SecOrchestrator enforces continuous verification:
```bash
# Run 111 unit & integration tests with >=80% coverage check
uv run pytest --cov=security_platform

# Code quality and style check
uv run ruff check .

# Strict type checking
uv run mypy --strict src/security_platform/

# Dogfooding: SecOrchestrator scanning its own codebase
uv run secorch scan src/ --format json
```

---

## License

SecOrchestrator is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
