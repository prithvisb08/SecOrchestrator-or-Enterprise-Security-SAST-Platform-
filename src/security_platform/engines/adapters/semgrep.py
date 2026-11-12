import json
import subprocess
import uuid
from pathlib import Path
from typing import Any

from security_platform.engines.base import Engine, is_binary_available
from security_platform.enums.severity import Severity
from security_platform.ingestion.models import RepositorySnapshot
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class SemgrepEngine(Engine):
    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def version(self) -> str:
        return "1.65.0"

    def is_available(self) -> bool:
        return is_binary_available("semgrep")

    def supports(self, snapshot: RepositorySnapshot) -> bool:
        # Semgrep supports multi-language (python, javascript, go, java, c, ruby, etc.)
        supported_langs = {"python", "javascript", "typescript", "go", "java", "ruby", "c", "cpp"}
        return any(f.language in supported_langs for f in snapshot.files)

    def _map_cwe_to_vuln_type(self, cwes: list[str], check_id: str) -> VulnerabilityType:
        check_lower = check_id.lower()
        cwe_str = " ".join(cwes).lower()

        if "cwe-89" in cwe_str or "sql" in check_lower:
            return VulnerabilityType.SQL_INJECTION
        if "cwe-78" in cwe_str or "command" in check_lower or "exec" in check_lower:
            return VulnerabilityType.COMMAND_INJECTION
        if "cwe-79" in cwe_str or "xss" in check_lower:
            return VulnerabilityType.CROSS_SITE_SCRIPTING
        if "cwe-502" in cwe_str or "deserialization" in check_lower or "pickle" in check_lower:
            return VulnerabilityType.INSECURE_DESERIALIZATION
        if "cwe-22" in cwe_str or "path-traversal" in check_lower:
            return VulnerabilityType.PATH_TRAVERSAL
        if "cwe-918" in cwe_str or "ssrf" in check_lower:
            return VulnerabilityType.SSRF
        if "cwe-328" in cwe_str or "cwe-327" in cwe_str or "crypto" in check_lower:
            return VulnerabilityType.INSECURE_CRYPTOGRAPHY
        if "cwe-798" in cwe_str or "secret" in check_lower:
            return VulnerabilityType.HARDCODED_SECRET
        return VulnerabilityType.DANGEROUS_API

    def parse_semgrep_json(self, raw_json: str, workspace: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not raw_json.strip():
            return findings

        try:
            data: dict[str, Any] = json.loads(raw_json)
        except json.JSONDecodeError:
            return findings

        for result in data.get("results", []):
            check_id = result.get("check_id", "semgrep-rule")
            extra = result.get("extra", {})
            raw_sev = str(extra.get("severity", "WARNING")).upper()
            sev = (
                Severity.CRITICAL
                if raw_sev == "ERROR" and "cwe-89" in str(extra.get("metadata", {})).lower()
                else Severity.HIGH
                if raw_sev == "ERROR"
                else Severity.MEDIUM
                if raw_sev == "WARNING"
                else Severity.LOW
            )

            raw_path = result.get("path", "")
            try:
                rel_path = str(Path(raw_path).relative_to(workspace))
            except ValueError:
                rel_path = raw_path

            start = result.get("start", {})
            end = result.get("end", {})
            line_no = int(start.get("line", 1))
            end_line = int(end.get("line", line_no))
            col = int(start.get("col", 1))
            end_col = int(end.get("col", col))

            msg = extra.get("message", "Semgrep security finding")
            metadata = extra.get("metadata", {})
            cwes: list[str] = metadata.get("cwe", [])
            if isinstance(cwes, str):
                cwes = [cwes]

            vuln_type = self._map_cwe_to_vuln_type(cwes, check_id)
            code_lines = extra.get("lines", "")

            finding = Finding(
                finding_id=str(uuid.uuid4()),
                rule_id=f"SEMGREP-{check_id}",
                category=Category.SECURITY,
                vulnerability_type=vuln_type,
                title=f"Semgrep: {check_id}",
                description=msg,
                severity=sev,
                confidence=0.88,
                location=SourceLocation(
                    file_path=rel_path,
                    start_line=line_no,
                    end_line=end_line,
                    start_column=col,
                    end_column=end_col
                ),
                code_snippet=code_lines.strip() if code_lines else None,
                evidence=f"Semgrep rule {check_id} matched on line {line_no}.",
                root_cause=msg,
                recommendation=f"Remediate according to Semgrep guidance. CWEs: {', '.join(cwes)}",
                scanner_version=self.version,
                metadata={"check_id": check_id, "engine": "semgrep", "cwes": ", ".join(cwes)},
            )
            findings.append(finding)

        return findings

    def run(self, workspace: Path, timeout_seconds: int = 60) -> list[Finding]:
        cmd = ["semgrep", "scan", "--json", "-q", str(workspace)]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False
        )
        return self.parse_semgrep_json(proc.stdout, workspace)
