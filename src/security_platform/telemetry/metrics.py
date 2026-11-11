from collections.abc import Sequence

from fastapi import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from security_platform.models.finding import Finding

# Metric definitions
SCAN_COUNTER = Counter(
    "security_platform_scans_total",
    "Total number of security scans executed",
    ["status"]
)

FINDINGS_COUNTER = Counter(
    "security_platform_findings_total",
    "Total security findings detected",
    ["severity", "vulnerability_type"]
)

SCAN_DURATION = Histogram(
    "security_platform_scan_duration_seconds",
    "Time spent executing repository scans"
)

class MetricsManager:
    """Manages application observability and Prometheus metric collection."""

    @staticmethod
    def record_scan(status: str, duration: float) -> None:
        SCAN_COUNTER.labels(status=status).inc()
        SCAN_DURATION.observe(duration)

    @staticmethod
    def record_findings(findings: Sequence[Finding]) -> None:
        for finding in findings:
            FINDINGS_COUNTER.labels(
                severity=finding.severity.value,
                vulnerability_type=str(finding.vulnerability_type)
            ).inc()

    @staticmethod
    def metrics_response() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
