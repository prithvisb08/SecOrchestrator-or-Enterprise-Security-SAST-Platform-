import json
from typing import Any

from security_platform.models.finding import Finding
from security_platform.risk.models import RiskAssessment


class ReportExporter:
    def to_json(self, repository_id: str, findings: list[Finding], risk: RiskAssessment) -> str:
        report = {
            "repository_id": repository_id,
            "risk_assessment": risk.model_dump(mode="json"),
            "findings_count": len(findings),
            "findings": [f.model_dump(mode="json") for f in findings]
        }
        return json.dumps(report, indent=2)

    def to_sarif(self, repository_id: str, findings: list[Finding]) -> str:
        results = []
        rules_map = {}

        for finding in findings:
            rules_map[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.description}
            }
            results.append({
                "ruleId": finding.rule_id,
                "level": self._map_severity_to_sarif(finding.severity),
                "message": {"text": finding.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.location.file_path},
                        "region": {
                            "startLine": finding.location.start_line,
                            "endLine": finding.location.end_line
                        }
                    }
                }]
            })

        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Enterprise Security Platform",
                        "version": "1.0.0",
                        "rules": list(rules_map.values())
                    }
                },
                "results": results
            }]
        }
        return json.dumps(sarif_report, indent=2)

    def _map_severity_to_sarif(self, severity: Any) -> str:
        mapping = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}
        sev_str = severity.value if hasattr(severity, "value") else str(severity)
        return mapping.get(str(sev_str).upper(), "warning")
