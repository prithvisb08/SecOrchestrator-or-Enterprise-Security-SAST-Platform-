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


class OSVScannerEngine(Engine):
    @property
    def name(self) -> str:
        return "osv-scanner"

    @property
    def version(self) -> str:
        return "1.7.0"

    def is_available(self) -> bool:
        return is_binary_available("osv-scanner")

    def supports(self, snapshot: RepositorySnapshot) -> bool:
        manifest_names = {"requirements.txt", "pyproject.toml", "package.json", "go.mod", "pom.xml", "Cargo.lock"}
        return any(Path(f.file_path).name in manifest_names for f in snapshot.files)

    def parse_osv_json(self, raw_json: str, workspace: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not raw_json.strip():
            return findings

        try:
            data: dict[str, Any] = json.loads(raw_json)
        except json.JSONDecodeError:
            return findings

        for result in data.get("results", []):
            source = result.get("source", {})
            path_str = source.get("path", "")
            try:
                rel_path = str(Path(path_str).relative_to(workspace))
            except ValueError:
                rel_path = path_str

            for pkg_wrapper in result.get("packages", []):
                pkg = pkg_wrapper.get("package", {})
                pkg_name = pkg.get("name", "unknown")
                pkg_version = pkg.get("version", "unknown")
                ecosystem = pkg.get("ecosystem", "generic")

                for vuln in pkg_wrapper.get("vulnerabilities", []):
                    vuln_id = vuln.get("id", "OSV-UNKNOWN")
                    summary = vuln.get("summary", f"Vulnerability {vuln_id} in {pkg_name}")
                    details = vuln.get("details", summary)
                    aliases: list[str] = vuln.get("aliases", [])

                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        rule_id=f"OSV-{vuln_id}",
                        category=Category.DEPENDENCIES,
                        vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                        title=f"OSV: {vuln_id} ({pkg_name}@{pkg_version})",
                        description=summary,
                        severity=Severity.HIGH,
                        confidence=0.95,
                        location=SourceLocation(file_path=rel_path, start_line=1, end_line=1),
                        code_snippet=f"{pkg_name}=={pkg_version}",
                        evidence=f"OSV database matched {vuln_id} (Aliases: {', '.join(aliases)}).",
                        root_cause=details,
                        recommendation=f"Upgrade {pkg_name} to the latest non-vulnerable release.",
                        scanner_version=self.version,
                        metadata={
                            "vuln_id": vuln_id,
                            "package": pkg_name,
                            "version": pkg_version,
                            "ecosystem": ecosystem,
                            "engine": "osv-scanner",
                        },
                    )
                    findings.append(finding)

        return findings

    def run(self, workspace: Path, timeout_seconds: int = 60) -> list[Finding]:
        cmd = ["osv-scanner", "--json", "-r", str(workspace)]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False
        )
        return self.parse_osv_json(proc.stdout, workspace)
