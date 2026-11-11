import uuid

from security_platform.models.finding import Finding
from security_platform.risk.models import AttackPath, AttackPathNode, CorrelatedFinding


class FindingCorrelator:
    def correlate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        grouped_by_location: dict[str, list[Finding]] = {}
        for finding in findings:
            loc_key = f"{finding.location.file_path}:{finding.location.start_line}"
            grouped_by_location.setdefault(loc_key, []).append(finding)

        correlated_results = []
        for loc_key, group in grouped_by_location.items():
            primary = group[0]
            duplicates = group[1:]
            merged_evidence = [f.evidence for f in group if f.evidence]

            attack_path = None
            if any("Source" in (f.evidence or "") for f in group):
                attack_path = AttackPath(
                    path_id=str(uuid.uuid4()),
                    title=f"Exploit Path at {loc_key}",
                    nodes=[
                        AttackPathNode(step_number=1, component="External Input Source", description="HTTP Parameter / Data Input"),
                        AttackPathNode(step_number=2, component=primary.affected_component or "Application Logic", description="Unsafe Processing Function"),
                        AttackPathNode(step_number=3, component="Sensitive Sink", description=primary.title)
                    ]
                )

            correlated_results.append(CorrelatedFinding(
                correlation_id=str(uuid.uuid4()),
                primary_finding=primary,
                correlated_findings=duplicates,
                merged_evidence=merged_evidence,
                attack_path=attack_path
            ))

        return correlated_results
