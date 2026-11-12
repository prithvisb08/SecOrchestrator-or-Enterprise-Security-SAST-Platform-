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

BANDIT_TEST_TO_VULN_TYPE: dict[str, VulnerabilityType] = {
    "B602": VulnerabilityType.COMMAND_INJECTION,
    "B603": VulnerabilityType.COMMAND_INJECTION,
    "B604": VulnerabilityType.COMMAND_INJECTION,
    "B605": VulnerabilityType.COMMAND_INJECTION,
    "B606": VulnerabilityType.COMMAND_INJECTION,
    "B607": VulnerabilityType.COMMAND_INJECTION,
    "B608": VulnerabilityType.SQL_INJECTION,
    "B301": VulnerabilityType.INSECURE_DESERIALIZATION,
    "B302": VulnerabilityType.INSECURE_DESERIALIZATION,
    "B303": VulnerabilityType.INSECURE_CRYPTOGRAPHY,
    "B304": VulnerabilityType.INSECURE_CRYPTOGRAPHY,
    "B305": VulnerabilityType.INSECURE_CRYPTOGRAPHY,
    "B307": VulnerabilityType.CODE_INJECTION,
    "B105": VulnerabilityType.PASSWORD,
    "B106": VulnerabilityType.PASSWORD,
    "B107": VulnerabilityType.PASSWORD,
}


class BanditEngine(Engine):
    @property
    def name(self) -> str:
        return "bandit"

    @property
    def version(self) -> str:
        return "1.7.8"

    def is_available(self) -> bool:
        return is_binary_available("bandit")

    def supports(self, snapshot: RepositorySnapshot) -> bool:
        return any(f.language == "python" for f in snapshot.files)

    def parse_bandit_json(self, raw_json: str, workspace: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not raw_json.strip():
            return findings

        try:
            data: dict[str, Any] = json.loads(raw_json)
        except json.JSONDecodeError:
            return findings

        for result in data.get("results", []):
            test_id = result.get("test_id", "UNKNOWN")
            raw_sev = str(result.get("issue_severity", "MEDIUM")).upper()
            sev = (
                Severity.HIGH
                if raw_sev == "HIGH"
                else Severity.MEDIUM
                if raw_sev == "MEDIUM"
                else Severity.LOW
            )

            vuln_type = BANDIT_TEST_TO_VULN_TYPE.get(test_id, VulnerabilityType.DANGEROUS_API)
            filename = result.get("filename", "")
            try:
                rel_path = str(Path(filename).relative_to(workspace))
            except ValueError:
                rel_path = filename

            line_no = int(result.get("line_number", 1))
            code = result.get("code", "")
            text = result.get("issue_text", "Bandit security finding")
            more_info = result.get("more_info", "")

            finding = Finding(
                finding_id=str(uuid.uuid4()),
                rule_id=f"BANDIT-{test_id}",
                category=Category.SECURITY,
                vulnerability_type=vuln_type,
                title=f"Bandit: {text}",
                description=f"{text} (Rule {test_id})",
                severity=sev,
                confidence=0.85,
                location=SourceLocation(file_path=rel_path, start_line=line_no, end_line=line_no),
                code_snippet=code.strip() if code else None,
                evidence=f"Bandit finding {test_id} on line {line_no}.",
                root_cause=text,
                recommendation=f"Review and remediate according to Bandit guidelines: {more_info}",
                scanner_version=self.version,
                metadata={"test_id": test_id, "engine": "bandit"},
            )
            findings.append(finding)

        return findings

    def run(self, workspace: Path, timeout_seconds: int = 60) -> list[Finding]:
        cmd = ["bandit", "-r", str(workspace), "-f", "json", "-q"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False  # Bandit returns non-zero when vulnerabilities are found
        )
        return self.parse_bandit_json(proc.stdout, workspace)
