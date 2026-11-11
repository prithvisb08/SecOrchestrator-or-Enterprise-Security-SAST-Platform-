import ast
import uuid

from security_platform.dataflow.analyzer import TaintTracker
from security_platform.dataflow.config import DEFAULT_SINKS
from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class DataFlowEngine:
    def __init__(self, scanner_version: str = "1.0.0"):
        self.scanner_version = scanner_version

    def analyze_file(self, file_path: str, source_code: str) -> list[Finding]:
        findings = []
        try:
            tree = ast.parse(source_code)
            tracker = TaintTracker(file_path)
            tracker.visit(tree)

            for path in tracker.discovered_paths:
                sink_info = DEFAULT_SINKS.get(path.sink.expression)
                if not sink_info:
                    continue
                v_type = (
                    sink_info.vulnerability_type
                    if isinstance(sink_info.vulnerability_type, VulnerabilityType)
                    else VulnerabilityType(sink_info.vulnerability_type)
                )
                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    rule_id=f"SEC-TAINT-{str(v_type).upper()}-001",
                    category=Category.SECURITY,
                    vulnerability_type=v_type,
                    title=f"Untrusted Data Reaches {path.sink.expression}",
                    description=f"Data originating from {path.source.expression} flows into {path.sink.expression} without sanitization.",
                    severity=Severity.HIGH,
                    confidence=0.90,
                    location=path.sink.location,
                    root_cause="Missing input validation or sanitization before a sensitive sink.",
                    evidence=f"Source: {path.source.expression} (Line {path.source.location.start_line}) -> Sink: {path.sink.expression} (Line {path.sink.location.start_line})",
                    recommendation="Apply context-aware escaping, parameterization, or validation before this operation.",
                    scanner_version=self.scanner_version
                )
                findings.append(finding)
        except SyntaxError:
            pass
        return findings
