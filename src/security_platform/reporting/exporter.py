import hashlib
import json
import re
from typing import Any

from security_platform.core.version import get_version
from security_platform.models.finding import Finding
from security_platform.risk.models import RiskAssessment

SECURITY_SEVERITY_NUMERIC = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "2.5",
    "INFO": "1.0"
}


class ReportExporter:
    """Exports scan results into JSON and OASIS SARIF v2.1.0 formats."""

    def to_json(self, repository_id: str, findings: list[Finding], risk: RiskAssessment) -> str:
        report = {
            "repository_id": repository_id,
            "risk_assessment": risk.model_dump(mode="json"),
            "findings_count": len(findings),
            "findings": [f.model_dump(mode="json") for f in findings]
        }
        return json.dumps(report, indent=2)

    def _extract_cwe_id(self, finding: Finding) -> str | None:
        """Extracts standard CWE number from rule ID or metadata."""
        cwe_str = finding.metadata.get("cwes") or finding.metadata.get("cwe") or finding.rule_id
        match = re.search(r"CWE-?(\d+)", cwe_str, re.IGNORECASE)
        return match.group(1) if match else None

    def to_sarif(
        self,
        repository_id: str,
        findings: list[Finding],
        scan_id: str | None = None
    ) -> str:
        version = get_version()
        results: list[dict[str, Any]] = []
        rules_map: dict[str, dict[str, Any]] = {}

        for finding in findings:
            cwe_id = self._extract_cwe_id(finding)
            tags = ["security"]
            help_uri = "https://cwe.mitre.org/"
            if cwe_id:
                tags.append(f"external/cwe/cwe-{cwe_id}")
                help_uri = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

            sev_str = str(finding.severity.value).upper()
            sec_severity = SECURITY_SEVERITY_NUMERIC.get(sev_str, "5.0")

            rules_map[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "helpUri": help_uri,
                "help": {
                    "text": finding.recommendation or finding.description,
                    "markdown": (
                        f"### {finding.title}\n\n"
                        f"**Root Cause:** {finding.root_cause or 'Unspecified'}\n\n"
                        f"**Recommendation:** {finding.recommendation or 'Remediate security issue.'}"
                    )
                },
                "properties": {
                    "tags": tags,
                    "security-severity": sec_severity,
                    "precision": "high" if finding.confidence >= 0.85 else "medium"
                }
            }

            # Stable partial fingerprints for GitHub alert tracking
            snippet_text = (finding.code_snippet or "").strip()
            line_hash = hashlib.sha256(snippet_text.encode("utf-8")).hexdigest()[:16]
            stable_fp = finding.get_fingerprint()

            physical_region: dict[str, Any] = {
                "startLine": finding.location.start_line,
                "endLine": finding.location.end_line,
                "startColumn": finding.location.start_column or 1,
                "endColumn": finding.location.end_column or 1,
            }
            if finding.code_snippet:
                physical_region["snippet"] = {"text": finding.code_snippet}

            results.append({
                "ruleId": finding.rule_id,
                "level": self._map_severity_to_sarif(finding.severity),
                "message": {"text": finding.description},
                "partialFingerprints": {
                    "primaryLocationLineHash": line_hash,
                    "secorchFingerprint/v1": stable_fp
                },
                "properties": {
                    "confidence": finding.confidence,
                    "vulnerability_type": str(finding.vulnerability_type)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location.file_path.replace("\\", "/")
                        },
                        "region": physical_region
                    }
                }]
            })

        sarif_report: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SecOrchestrator",
                        "semanticVersion": version,
                        "informationUri": "https://github.com/secorchestrator/secorchestrator",
                        "rules": list(rules_map.values())
                    }
                },
                "automationDetails": {
                    "id": f"secorch/{repository_id}/{scan_id or 'latest'}"
                },
                "invocations": [{
                    "executionSuccessful": True,
                    "toolExecutionNotifications": []
                }],
                "results": results
            }]
        }
        return json.dumps(sarif_report, indent=2)

    def _map_severity_to_sarif(self, severity: Any) -> str:
        mapping = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}
        sev_str = severity.value if hasattr(severity, "value") else str(severity)
        return mapping.get(str(sev_str).upper(), "warning")
