from collections.abc import Sequence

from fastapi import Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

from security_platform.models.finding import Finding

# Metric definitions
SCAN_COUNTER = Counter(
    "security_platform_scans_total",
    "Total number of security scans executed",
    ["status"],
)

FINDINGS_COUNTER = Counter(
    "security_platform_findings_total",
    "Total security findings detected",
    ["severity", "vulnerability_type"],
)

FINDINGS_BY_ENGINE_COUNTER = Counter(
    "security_platform_findings_by_engine_total",
    "Findings detected tagged by engine",
    ["severity", "engine"],
)

ENGINE_FAILURES_COUNTER = Counter(
    "security_platform_engine_failures_total",
    "Total number of external engine execution failures",
    ["engine_name"],
)

QUEUE_DEPTH_GAUGE = Gauge(
    "security_platform_queue_depth",
    "Current number of pending scans in worker job queue",
)

SCAN_DURATION = Histogram(
    "security_platform_scan_duration_seconds",
    "Time spent executing repository scans",
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
                vulnerability_type=str(finding.vulnerability_type),
            ).inc()
            engine = finding.metadata.get("engine", "internal") if finding.metadata else "internal"
            FINDINGS_BY_ENGINE_COUNTER.labels(
                severity=finding.severity.value,
                engine=engine,
            ).inc()

    @staticmethod
    def record_engine_failure(engine_name: str) -> None:
        ENGINE_FAILURES_COUNTER.labels(engine_name=engine_name).inc()

    @staticmethod
    def set_queue_depth(depth: int) -> None:
        QUEUE_DEPTH_GAUGE.set(depth)

    @staticmethod
    def metrics_response() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
