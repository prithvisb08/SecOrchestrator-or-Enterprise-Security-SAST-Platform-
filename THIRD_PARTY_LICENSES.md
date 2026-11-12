# Third-Party Licenses

This document tracks all external tools and libraries utilized or integrated into SecOrchestrator, their source repository, license type, and verification notes.

## Runtime & Platform Dependencies

| Dependency | License | Source Repository | Verification Notes |
|------------|---------|-------------------|-------------------|
| FastAPI | MIT | [tiangolo/fastapi](https://github.com/tiangolo/fastapi) | Permissive |
| Uvicorn | BSD-3-Clause | [encode/uvicorn](https://github.com/encode/uvicorn) | Permissive |
| Pydantic v2 | MIT | [pydantic/pydantic](https://github.com/pydantic/pydantic) | Permissive |
| Typer | MIT | [tiangolo/typer](https://github.com/tiangolo/typer) | Permissive |
| Rich | MIT | [Textualize/rich](https://github.com/Textualize/rich) | Permissive |
| Prometheus Client | Apache-2.0 | [prometheus/client_python](https://github.com/prometheus/client_python) | Permissive |
| PyJWT | Apache-2.0 | [jpadilla/pyjwt](https://github.com/jpadilla/pyjwt) | Permissive |
| python-multipart | Apache-2.0 | [Kludex/python-multipart](https://github.com/Kludex/python-multipart) | Permissive |
| PyYAML | MIT | [yaml/pyyaml](https://github.com/yaml/pyyaml) | Permissive |
| SQLAlchemy | MIT | [sqlalchemy/sqlalchemy](https://github.com/sqlalchemy/sqlalchemy) | Permissive |
| LibCST | MIT | [Instagram/LibCST](https://github.com/Instagram/LibCST) | Permissive |

## Development & Testing Dependencies

| Dependency | License | Source Repository | Verification Notes |
|------------|---------|-------------------|-------------------|
| pytest | MIT | [pytest-dev/pytest](https://github.com/pytest-dev/pytest) | Permissive |
| pytest-cov | MIT | [pytest-dev/pytest-cov](https://github.com/pytest-dev/pytest-cov) | Permissive |
| httpx | BSD-3-Clause | [encode/httpx](https://github.com/encode/httpx) | Permissive |
| ruff | MIT / Apache-2.0 | [astral-sh/ruff](https://github.com/astral-sh/ruff) | Permissive |
| mypy | MIT | [python/mypy](https://github.com/python/mypy) | Permissive |

## Planned External Orchestrated Engines (Audit Status)

| Tool | Purpose | License | Commercial / SaaS Note |
|------|---------|---------|------------------------|
| Bandit | Python SAST baseline | Apache-2.0 | Permissive |
| Gitleaks | Secret detection in git history | MIT | Permissive |
| OSV-Scanner | Dependency CVE scanning | Apache-2.0 | Permissive |
| Syft | SBOM generation (CycloneDX/SPDX) | Apache-2.0 | Permissive |
| Trivy | Container & IaC scanner | Apache-2.0 | Permissive |
| Checkov | IaC security policy | Apache-2.0 | Permissive |
| Semgrep CLI | Multi-language SAST | LGPL-2.1 | Engine invoked via CLI subprocess. Custom/permissive rulesets required for commercial SaaS distribution. |
| Hadolint | Dockerfile linter | GPL-3.0 | Invoked as standalone binary only; confirm legal guidance before redistribution. |
| TruffleHog | Secret verification | AGPL-3.0 | **FLAGGED**: Copyleft restrictions for network/hosted services. Requires explicit user approval before integration. |
