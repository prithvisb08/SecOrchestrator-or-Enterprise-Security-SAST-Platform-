# ADR-002: Comment-Preserving Concrete Syntax Trees (LibCST) for Auto-Remediation

## Status
Accepted

## Context
Standard library Python `ast.unparse()` strips all developer comments, reformats blank lines, and destroys original whitespace. Applying security fixes via standard AST generation causes massive code churn and creates unacceptable merge conflicts.

## Decision
We implemented automated security remediation using LibCST (`libcst.CSTTransformer`).
LibCST constructs a Concrete Syntax Tree (CST) that guarantees 100% preservation of all existing comments, docstrings, formatting, and indentation.

## Remediated Patterns
- `yaml.load(...)` -> `yaml.safe_load(...)`
- `hashlib.md5(...)` / `hashlib.sha1(...)` -> `hashlib.sha256(...)` (when `usedforsecurity=False` is absent)
- `subprocess.*(..., shell=True)` -> `shell=False`
- Simple dynamic SQL queries -> Parameterized prepared statements with `%s` tuple arguments.
