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

TRIVY_SEV_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class TrivyEngine(Engine):
    @property
    def name(self) -> str:
        return "trivy"

    @property
    def version(self) -> str:
        return "0.50.0"

    def is_available(self) -> bool:
        return is_binary_available("trivy")

    def supports(self, snapshot: RepositorySnapshot) -> bool:
        return True  # Scans dependencies, containers, and config

    def parse_trivy_json(self, raw_json: str, workspace: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not raw_json.strip():
            return findings

        try:
            data: dict[str, Any] = json.loads(raw_json)
        except json.JSONDecodeError:
            return findings

        for result in data.get("Results", []):
            target = result.get("Target", "workspace")
            try:
                rel_path = str(Path(target).relative_to(workspace))
            except ValueError:
                rel_path = target

            # 1. Dependency vulnerabilities
            for vuln in result.get("Vulnerabilities", []):
                vuln_id = vuln.get("VulnerabilityID", "CVE-UNKNOWN")
                pkg_name = vuln.get("PkgName", "")
                installed_ver = vuln.get("InstalledVersion", "")
                fixed_ver = vuln.get("FixedVersion", "")
                raw_sev = str(vuln.get("Severity", "MEDIUM")).upper()
                sev = TRIVY_SEV_MAP.get(raw_sev, Severity.MEDIUM)
                title = vuln.get("Title", f"Vulnerability in {pkg_name}")

                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    rule_id=f"TRIVY-{vuln_id}",
                    category=Category.DEPENDENCIES,
                    vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                    title=f"Trivy: {vuln_id} ({pkg_name})",
                    description=f"{title}. Installed version: {pkg_name}@{installed_ver}.",
                    severity=sev,
                    confidence=0.95,
                    location=SourceLocation(file_path=rel_path, start_line=1, end_line=1),
                    code_snippet=f"{pkg_name}=={installed_ver}",
                    evidence=f"Trivy detected {vuln_id} in {pkg_name}@{installed_ver} (Fixed in: {fixed_ver or 'None'}).",
                    root_cause=f"Vulnerable library {pkg_name}@{installed_ver} in {rel_path}.",
                    recommendation=f"Upgrade {pkg_name} to {fixed_ver or 'latest secure version'}.",
                    scanner_version=self.version,
                    metadata={"vulnerability_id": vuln_id, "package": pkg_name, "engine": "trivy"},
                )
                findings.append(finding)

            # 2. Misconfigurations (IaC & Docker)
            for misconf in result.get("Misconfigurations", []):
                mis_id = misconf.get("ID", "MISCONF")
                title = misconf.get("Title", "Security Misconfiguration")
                desc = misconf.get("Description", "")
                raw_sev = str(misconf.get("Severity", "MEDIUM")).upper()
                sev = TRIVY_SEV_MAP.get(raw_sev, Severity.MEDIUM)

                start_line = int(misconf.get("IacMetadata", {}).get("StartLine", 1))

                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    rule_id=f"TRIVY-{mis_id}",
                    category=Category.CONFIGURATION,
                    vulnerability_type=VulnerabilityType.MISCONFIGURATION,
                    title=f"Trivy: {title}",
                    description=desc,
                    severity=sev,
                    confidence=0.90,
                    location=SourceLocation(file_path=rel_path, start_line=start_line, end_line=start_line),
                    evidence=f"Misconfiguration {mis_id} on line {start_line}.",
                    root_cause=desc,
                    recommendation=misconf.get("Resolution", "Correct the configuration directive."),
                    scanner_version=self.version,
                    metadata={"misconf_id": mis_id, "engine": "trivy"},
                )
                findings.append(finding)

        return findings

    def run(self, workspace: Path, timeout_seconds: int = 60) -> list[Finding]:
        cmd = ["trivy", "fs", "--format", "json", "-q", str(workspace)]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False
        )
        return self.parse_trivy_json(proc.stdout, workspace)
