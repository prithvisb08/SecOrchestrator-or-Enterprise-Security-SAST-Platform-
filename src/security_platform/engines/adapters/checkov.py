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


class CheckovEngine(Engine):
    @property
    def name(self) -> str:
        return "checkov"

    @property
    def version(self) -> str:
        return "3.2.0"

    def is_available(self) -> bool:
        return is_binary_available("checkov")

    def supports(self, snapshot: RepositorySnapshot) -> bool:
        # Checkov supports Dockerfile, Terraform (.tf), CloudFormation, K8s (.yaml), etc.
        iac_extensions = {".tf", ".yaml", ".yml", ".json"}
        return any(
            "Dockerfile" in f.file_path or Path(f.file_path).suffix in iac_extensions
            for f in snapshot.files
        )

    def parse_checkov_json(self, raw_json: str, workspace: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not raw_json.strip():
            return findings

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return findings

        # Checkov output can be a single dict or a list of dicts (for multiple frameworks)
        results_list: list[dict[str, Any]] = [data] if isinstance(data, dict) else data

        for block in results_list:
            results_dict = block.get("results", {}) if isinstance(block, dict) else {}
            for check in results_dict.get("failed_checks", []):
                check_id = check.get("check_id", "CKV_UNKNOWN")
                check_name = check.get("check_name", "Checkov policy violation")
                file_path = check.get("file_path", "")
                try:
                    rel_path = str(Path(file_path).relative_to(workspace))
                except ValueError:
                    rel_path = file_path.lstrip("/")

                lines = check.get("file_line_range", [1, 1])
                start_line = lines[0] if lines else 1
                end_line = lines[1] if len(lines) > 1 else start_line

                raw_sev = str(check.get("severity", "MEDIUM") or "MEDIUM").upper()
                sev = (
                    Severity.CRITICAL
                    if raw_sev == "CRITICAL"
                    else Severity.HIGH
                    if raw_sev == "HIGH"
                    else Severity.MEDIUM
                    if raw_sev == "MEDIUM"
                    else Severity.LOW
                )

                guideline = check.get("guideline", "Review Checkov policy recommendation.")
                vuln_type = (
                    VulnerabilityType.INSECURE_DOCKER
                    if "DOCKER" in check_id
                    else VulnerabilityType.MISCONFIGURATION
                )

                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    rule_id=f"CHECKOV-{check_id}",
                    category=Category.CONFIGURATION,
                    vulnerability_type=vuln_type,
                    title=f"Checkov: {check_name}",
                    description=f"{check_name} ({check_id})",
                    severity=sev,
                    confidence=0.90,
                    location=SourceLocation(file_path=rel_path, start_line=start_line, end_line=end_line),
                    evidence=f"Failed check {check_id} on lines {start_line}-{end_line}.",
                    root_cause=check_name,
                    recommendation=guideline,
                    scanner_version=self.version,
                    metadata={"check_id": check_id, "engine": "checkov"},
                )
                findings.append(finding)

        return findings

    def run(self, workspace: Path, timeout_seconds: int = 60) -> list[Finding]:
        cmd = ["checkov", "-d", str(workspace), "-o", "json", "--compact"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False
        )
        return self.parse_checkov_json(proc.stdout, workspace)
