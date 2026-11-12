import hashlib

from security_platform.enums.status import FindingStatus
from security_platform.models.finding import Finding


def compute_stable_fingerprint(finding: Finding) -> str:
    """
    Computes an immutable, deterministic finding fingerprint across scanners and runs:
    hash(canonical_vulnerability_type + normalized_file_path + line_number + code_hash)
    """
    # Prefer existing explicitly assigned fingerprint
    if finding.fingerprint:
        return finding.fingerprint

    # Canonical vulnerability family
    vuln_family = str(finding.vulnerability_type).upper()

    # Normalized relative file path
    clean_path = finding.location.file_path.replace("\\", "/").strip("/.")

    # Location line
    line_no = str(finding.location.start_line)

    # Snippet hash (whitespace-normalized)
    snippet_content = (finding.code_snippet or "").strip()
    snippet_hash = hashlib.sha256(snippet_content.encode("utf-8")).hexdigest()[:16]

    raw_seed = f"{vuln_family}:{clean_path}:{line_no}:{snippet_hash}"
    stable_hash = hashlib.sha256(raw_seed.encode("utf-8")).hexdigest()[:24]
    return f"secorch:v1:{stable_hash}"


class FindingDeduplicator:
    """Deduplicates findings across multiple engines and tracks lifecycle transitions."""

    @staticmethod
    def deduplicate(findings: list[Finding]) -> list[Finding]:
        """
        Groups findings by stable fingerprint and merges duplicates across scanning engines.
        Picks the highest-confidence finding as primary and preserves multi-engine attribution.
        """
        grouped: dict[str, list[Finding]] = {}
        for f in findings:
            fp = f.get_fingerprint() or compute_stable_fingerprint(f)
            f.fingerprint = fp
            grouped.setdefault(fp, []).append(f)

        deduped: list[Finding] = []
        for _fp, group in grouped.items():
            # Sort to select finding with highest confidence and severity
            primary = max(group, key=lambda item: (item.confidence, item.severity.value))
            other_engines = {f.metadata.get("engine", "native") for f in group if f.metadata.get("engine")}
            if other_engines:
                primary.metadata["engines"] = ", ".join(sorted(other_engines))

            # Merge evidence from other engines
            additional_evidences = [f.evidence for f in group if f.evidence and f.evidence != primary.evidence]
            if additional_evidences:
                primary.metadata["correlated_evidence"] = " | ".join(additional_evidences)

            deduped.append(primary)

        return deduped

    @staticmethod
    def compute_lifecycle(
        current_findings: list[Finding],
        previous_findings: list[Finding]
    ) -> tuple[list[Finding], list[Finding]]:
        """
        Computes lifecycle states across scan runs:
        - NEW: first detected in this scan
        - EXISTING: present in previous scan and still active
        - FIXED: was present in previous scan but no longer detected
        - REOPENED: was marked FIXED previously but has resurfaced
        Returns (updated_current_findings, resolved_findings).
        """
        prev_by_fp: dict[str, Finding] = {
            f.get_fingerprint() or compute_stable_fingerprint(f): f
            for f in previous_findings
        }

        updated_current: list[Finding] = []
        curr_fps: set[str] = set()

        for curr in current_findings:
            fp = curr.get_fingerprint() or compute_stable_fingerprint(curr)
            curr.fingerprint = fp
            curr_fps.add(fp)

            if fp in prev_by_fp:
                prev = prev_by_fp[fp]
                if prev.status == FindingStatus.RESOLVED:
                    curr.metadata["lifecycle"] = "REOPENED"
                    curr.status = FindingStatus.REOPENED
                else:
                    curr.metadata["lifecycle"] = "EXISTING"
                    curr.status = prev.status
            else:
                curr.metadata["lifecycle"] = "NEW"
                curr.status = FindingStatus.OPEN

            updated_current.append(curr)

        # Identify fixed findings
        fixed_findings: list[Finding] = []
        for prev_fp, prev_finding in prev_by_fp.items():
            if prev_fp not in curr_fps and prev_finding.status not in {FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE}:
                prev_finding.status = FindingStatus.RESOLVED
                prev_finding.metadata["lifecycle"] = "FIXED"
                fixed_findings.append(prev_finding)

        return updated_current, fixed_findings
