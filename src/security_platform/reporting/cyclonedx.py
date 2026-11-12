import datetime
import uuid
from typing import Any

from security_platform.core.version import get_version
from security_platform.engines.dependency_analyzer import Dependency
from security_platform.models.finding import Finding


class CycloneDXExporter:
    """Exports Software Bill of Materials (SBOM) in CycloneDX v1.5 JSON format."""

    @staticmethod
    def generate_sbom(
        project_name: str,
        dependencies: list[Dependency],
        findings: list[Finding] | None = None,
        scanner_version: str | None = None
    ) -> dict[str, Any]:
        version = scanner_version or get_version()
        timestamp = datetime.datetime.now(datetime.UTC).isoformat()
        bom_uuid = str(uuid.uuid4())

        components: list[dict[str, Any]] = []
        for dep in dependencies:
            purl = (
                f"pkg:pypi/{dep.name}@{dep.version}"
                if dep.ecosystem == "pip"
                else f"pkg:npm/{dep.name}@{dep.version}"
            )
            components.append({
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "purl": purl,
                "scope": "required" if not dep.is_transitive else "optional",
                "properties": [
                    {"name": "secorch:manifest", "value": dep.manifest_path},
                    {"name": "secorch:ecosystem", "value": dep.ecosystem}
                ]
            })

        vulnerabilities: list[dict[str, Any]] = []
        if findings:
            for f in findings:
                cve = f.metadata.get("cve") if f.metadata else None
                if cve:
                    vulnerabilities.append({
                        "id": cve,
                        "source": {"name": "NVD"},
                        "ratings": [
                            {
                                "severity": str(f.severity).lower(),
                                "score": 9.0 if f.severity.value == "CRITICAL" else 7.5
                            }
                        ],
                        "description": f.description,
                        "recommendation": f.recommendation,
                        "affects": [
                            {"ref": f.code_snippet}
                        ]
                    })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{bom_uuid}",
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [
                    {
                        "vendor": "SecOrchestrator",
                        "name": "SecOrchestrator SAST Platform",
                        "version": version
                    }
                ],
                "component": {
                    "type": "application",
                    "name": project_name,
                    "version": "1.0.0"
                }
            },
            "components": components,
            "vulnerabilities": vulnerabilities
        }
