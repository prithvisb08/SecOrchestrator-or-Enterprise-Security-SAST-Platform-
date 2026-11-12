# Contributing to SecOrchestrator

Thank you for your interest in contributing to SecOrchestrator! This project maintains strict production-grade security, code quality, and testing standards.

## 1. Development Environment Setup

1. Install [uv](https://astral.sh/uv) (fast Python package manager).
2. Clone the repository and install dependencies:
   ```bash
   git clone https://github.com/secorchestrator/secorchestrator.git
   cd secorchestrator
   uv sync --extra dev
   ```
3. Set up pre-commit hooks:
   ```bash
   uv run pre-commit install
   ```

## 2. Coding Guidelines & Standards

- **Code Style:** We enforce `ruff` with 100-character line lengths. Run `uv run ruff check .` before submitting.
- **Type Checking:** All code in `src/security_platform/` must pass `uv run mypy --strict`.
- **Test-Driven Security Logic:** All new rules or security engines MUST include True-Positive and True-Negative tests.
- **Zero Secrets Policy:** Never commit real secrets, private keys, or API tokens. Test fixtures must use synthetic, dummy identifiers.
- **Third-Party Dependencies:** New dependencies must have permissive licenses (MIT, Apache-2.0, BSD-3-Clause) documented in `THIRD_PARTY_LICENSES.md`.

## 3. Running Verification Suite

Before opening a pull request, verify that all checks pass:
```bash
# 1. Tests & Coverage (must maintain >= 80% coverage)
uv run pytest --cov=security_platform

# 2. Linting & Formatting
uv run ruff check .

# 3. Strict Type Check
uv run mypy --strict src/security_platform/

# 4. Dogfooding Self-Scan
uv run secorch scan src/ --format json
```

## 4. Conventional Commits

We follow the Conventional Commits specification:
- `feat(module): description`
- `fix(module): description`
- `chore(module): description`
- `docs(module): description`
- `test(module): description`
