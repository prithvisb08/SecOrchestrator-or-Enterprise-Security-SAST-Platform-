# SecOrchestrator — Enterprise Security SAST Platform

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-red.svg)](SECURITY.md)

SecOrchestrator is a production-grade, multi-tenant Static Application Security Testing (SAST) and orchestration platform built with Python 3.12, FastAPI, Typer, and Pydantic v2. It coordinates native static analysis engines (inter-procedural taint analysis, secrets detection, weak cryptography, Dockerfile/IaC linting) alongside industry-standard open-source analyzers (Semgrep, Bandit, Gitleaks, Trivy, OSV-Scanner).

---

## Key Capabilities

- **Unified Scan Pipeline**: A single `ScanOrchestrator` powering both high-throughput API workers and the developer-centric CLI (`sec-scan`).
- **Deep Taint & Data Flow Analysis**: AST-based source-to-sink tracking with framework-specific taint sources, sanitizers, and dangerous execution sinks.
- **Multi-Engine Orchestration**: Pluggable engine architecture normalizing all findings into a unified, SARIF-compatible domain model.
- **Automated Remediation**: Deterministic AST refactoring and auto-PR generation for common security vulnerabilities (e.g., upgrading broken hash algorithms, parameterized queries).
- **Enterprise Reporting**: Native exports to SARIF 2.1.0 (with GitHub code-scanning annotations), structured JSON, and CI/CD PR review comments.
- **Production-Ready Observability**: Prometheus metrics, OpenTelemetry tracing, and structured logging.

---

## Architecture Overview

```
┌────────────────┐      ┌─────────────────────────┐      ┌───────────────────────────┐
│  CLI / CI / UI │ ───▶ │       FastAPI API       │ ───▶ │   Worker / Orchestrator   │
└────────────────┘      │  (Auth, RBAC, Limiting) │      │  (Native + OSS Engines)   │
                        └────────────┬────────────┘      └─────────────┬─────────────┘
                                     │                                 │
                                     ▼                                 ▼
                        ┌─────────────────────────┐      ┌───────────────────────────┐
                        │    PostgreSQL / Redis   │      │ Normalized SARIF & JSON   │
                        │  (Tenants, Findings)    │      │ Reports / Policy Gating   │
                        └─────────────────────────┘      └───────────────────────────┘
```

---

## Quick Start

### Installation

Requires Python 3.12+:

```bash
# Clone the repository
git clone https://github.com/example/SecOrchestrator.git
cd SecOrchestrator

# Install with dependencies using uv or pip
uv pip install -e ".[dev]"
```

### CLI Usage

```bash
# Scan a directory or file
sec-scan scan /path/to/project --format json --output report.json

# Scan and output SARIF for GitHub Code Scanning
sec-scan scan /path/to/project --format sarif --output report.sarif

# Enforce a security quality gate
sec-scan scan /path/to/project --fail-on high
```

### Running the API

```bash
uvicorn security_platform.api.app:app --host 0.0.0.0 --port 8000 --reload
```

Interactive documentation is available at `http://localhost:8000/docs`.

---

## Running Tests

```bash
uv run --extra dev pytest --cov=src/security_platform
```
