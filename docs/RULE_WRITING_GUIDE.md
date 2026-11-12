# SecOrchestrator SAST Rule Writing Guide

This guide describes how to author custom static analysis, dataflow taint, and secret detection rules for SecOrchestrator.

## 1. Architecture of a Detection Rule

Every rule inherits from `BaseRule` and specifies standard taxonomy metadata:
- `rule_id`: Unique string (e.g. `SEC-INJ-SQL-001`, `SEC-CRYPTO-001`).
- `category`: Taxonomy Category (`SECURITY`, `SECRETS`, `DEPENDENCY`, `CODE_QUALITY`, `CONFIGURATION`).
- `vulnerability_type`: VulnerabilityType enum (e.g. `SQL_INJECTION`, `HARDCODED_SECRET`).
- `severity`: Severity enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `confidence`: Float between 0.0 and 1.0.

## 2. YAML Source & Sink Specification (`sources_sinks.yaml`)

Framework sources and sinks are declared declaratively in versioned YAML packs:

```yaml
sources:
  flask:
    - name: request.args
      description: "Flask query string parameters"
    - name: request.form
      description: "Flask POST body form values"

sinks:
  sql_injection:
    - name: sqlite3.Cursor.execute
      sanitizers:
        - int
        - float
        - str.isnumeric

  command_injection:
    - name: subprocess.run
      sanitizers:
        - shlex.quote
```

## 3. AST Pattern Rules

To author a custom AST rule:
1. Implement `analyze_file(self, file_path: str, content: str) -> list[Finding]`.
2. Inspect AST Call, Attribute, or Assign nodes using `ast.walk` or `ast.NodeVisitor`.
3. Check context such as `usedforsecurity=False` to downgrade or suppress false positives.
4. Return normalized `Finding` objects with precise `SourceLocation`.

## 4. Test-Driven Rule Development

Every new rule MUST include:
1. True-Positive unit test proving the vulnerability is caught.
2. True-Negative unit test proving properly sanitized code does NOT produce a finding.
