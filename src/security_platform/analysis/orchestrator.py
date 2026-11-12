import json
import re
import time
import uuid
from pathlib import Path

from pydantic import BaseModel, Field

from security_platform.core.logging import logger
from security_platform.core.version import get_version
from security_platform.dataflow.engine import DataFlowEngine
from security_platform.engines.config_analyzer import ConfigurationAnalyzer
from security_platform.engines.dependency_analyzer import Dependency, DependencyAnalyzer
from security_platform.engines.secret_scanner import SecretScanner
from security_platform.ingestion.snapshot import RepositorySnapshotBuilder
from security_platform.intelligence.context import AnalyzerContext
from security_platform.models.finding import Finding
from security_platform.risk.correlator import FindingCorrelator
from security_platform.risk.engine import RiskEngine
from security_platform.risk.models import CorrelatedFinding, RiskAssessment
from security_platform.sast.engine import SASTEngine
from security_platform.sast.rules.unsafe_execution import UnsafeEvalExecRule
from security_platform.sast.rules.weak_cryptography import WeakHashingRule


class ScanErrorEntry(BaseModel):
    file_path: str
    error_type: str
    message: str


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repository_id: str
    status: str  # "COMPLETED", "PARTIAL", "FAILED"
    scanner_version: str
    findings: list[Finding] = Field(default_factory=list)
    findings_count: int = 0
    dependencies: list[Dependency] = Field(default_factory=list)
    correlated_findings: list[CorrelatedFinding] = Field(default_factory=list)
    risk_assessment: RiskAssessment
    scan_errors: list[ScanErrorEntry] = Field(default_factory=list)
    scanned_files_count: int = 0
    duration_seconds: float = 0.0


class ScanOrchestrator:
    """Unified engine coordinator for both CLI and API workflows."""

    def __init__(self, scanner_version: str | None = None) -> None:
        self.version = scanner_version or get_version()
        self.secret_scanner = SecretScanner(scanner_version=self.version)
        self.config_analyzer = ConfigurationAnalyzer()
        self.dataflow_engine = DataFlowEngine(scanner_version=self.version)
        self.dependency_analyzer = DependencyAnalyzer(scanner_version=self.version)
        self.sast_engine = SASTEngine([UnsafeEvalExecRule(), WeakHashingRule()])
        self.correlator = FindingCorrelator()
        self.risk_engine = RiskEngine()

    def _filter_suppressions(self, workspace_path: Path, findings: list[Finding]) -> list[Finding]:
        """Filters out findings suppressed via inline comments or .secorch-baseline.json."""
        # Check for baseline file
        baseline_fingerprints: set[str] = set()
        baseline_file = (
            workspace_path / ".secorch-baseline.json"
            if workspace_path.is_dir()
            else (workspace_path.parent / ".secorch-baseline.json")
        )
        if baseline_file.exists():
            try:
                raw_baseline = json.loads(baseline_file.read_text(encoding="utf-8"))
                for entry in raw_baseline.get("findings", []):
                    fp = entry.get("fingerprint") or entry.get("rule_id")
                    if fp:
                        baseline_fingerprints.add(fp)
            except Exception:
                pass

        file_lines_cache: dict[str, list[str]] = {}
        unsuppressed: list[Finding] = []

        for finding in findings:
            fp = finding.get_fingerprint()
            if fp in baseline_fingerprints or finding.rule_id in baseline_fingerprints:
                continue

            file_path_str = finding.location.file_path
            if file_path_str not in file_lines_cache:
                p = workspace_path if workspace_path.is_file() else (workspace_path / file_path_str)
                if p.exists():
                    try:
                        file_lines_cache[file_path_str] = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                    except Exception:
                        file_lines_cache[file_path_str] = []
                else:
                    file_lines_cache[file_path_str] = []

            lines = file_lines_cache[file_path_str]
            line_idx = finding.location.start_line

            # Check finding line and immediate preceding line for inline suppression comment
            candidate_lines: list[str] = []
            if 1 <= line_idx <= len(lines):
                candidate_lines.append(lines[line_idx - 1])
            if line_idx >= 2 and line_idx - 1 <= len(lines):
                candidate_lines.append(lines[line_idx - 2])

            is_ignored = False
            for cl in candidate_lines:
                if "# secorch: ignore" in cl or "# secorch:ignore" in cl:
                    match = re.search(r"#\s*secorch:\s*ignore(?:\[([^\]]+)\])?", cl)
                    if match:
                        rule_spec = match.group(1)
                        if not rule_spec:
                            is_ignored = True
                            break
                        spec_upper = rule_spec.strip().upper()
                        if spec_upper in {finding.rule_id.upper(), str(finding.vulnerability_type).upper()}:
                            is_ignored = True
                            break

            if not is_ignored:
                unsuppressed.append(finding)

        return unsuppressed

    def run_scan(
        self,
        target_path: Path | str,
        asset_criticality: float = 1.0,
        scan_id: str | None = None,
        repository_id: str | None = None
    ) -> ScanResult:
        start_time = time.monotonic()
        path = Path(target_path).resolve()
        scan_id = scan_id or str(uuid.uuid4())
        repo_id = repository_id or path.name

        logger.info("Scan started", extra={"scan_id": scan_id, "target": str(path)})

        if not path.exists():
            duration = round(time.monotonic() - start_time, 3)
            dummy_risk = self.risk_engine.calculate_risk(repo_id, [], asset_criticality)
            return ScanResult(
                scan_id=scan_id,
                repository_id=repo_id,
                status="FAILED",
                scanner_version=self.version,
                risk_assessment=dummy_risk,
                scan_errors=[
                    ScanErrorEntry(
                        file_path=str(path),
                        error_type="FileNotFoundError",
                        message=f"Target path does not exist: {path}"
                    )
                ],
                duration_seconds=duration
            )

        # 1. Ingest repository snapshot
        builder = RepositorySnapshotBuilder(path)
        snapshot = builder.build_snapshot(repository_id=repo_id)
        context = AnalyzerContext(path, snapshot)

        all_findings: list[Finding] = []
        all_dependencies: list[Dependency] = []
        scan_errors: list[ScanErrorEntry] = []

        # 2. Iterate and scan files
        for file_inv in snapshot.files:
            full_path = path if path.is_file() else (path / file_inv.file_path)
            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
            except Exception as exc:
                logger.warning(
                    "Failed to read file",
                    extra={"scan_id": scan_id, "file_path": file_inv.file_path, "error": str(exc)}
                )
                scan_errors.append(
                    ScanErrorEntry(
                        file_path=file_inv.file_path,
                        error_type=type(exc).__name__,
                        message=str(exc)
                    )
                )
                continue

            # Secret scanner
            try:
                all_findings.extend(
                    self.secret_scanner.scan_content(file_inv.file_path, content)
                )
            except Exception as exc:
                logger.error("Secret scanner failed on file", extra={"file": file_inv.file_path, "error": str(exc)})
                scan_errors.append(
                    ScanErrorEntry(
                        file_path=file_inv.file_path,
                        error_type=f"SecretScanner.{type(exc).__name__}",
                        message=str(exc)
                    )
                )

            # Dockerfile analysis
            if "Dockerfile" in file_inv.file_path:
                try:
                    all_findings.extend(
                        self.config_analyzer.analyze_dockerfile(file_inv.file_path, content)
                    )
                except Exception as exc:
                    logger.error("Config analyzer failed on file", extra={"file": file_inv.file_path, "error": str(exc)})
                    scan_errors.append(
                        ScanErrorEntry(
                            file_path=file_inv.file_path,
                            error_type=f"ConfigAnalyzer.{type(exc).__name__}",
                            message=str(exc)
                        )
                    )

            # SCA Dependency manifest analysis
            if any(file_inv.file_path.endswith(m) for m in ["requirements.txt", "pyproject.toml", "package.json"]):
                try:
                    deps, sca_findings = self.dependency_analyzer.scan_manifest(file_inv.file_path, content)
                    all_dependencies.extend(deps)
                    all_findings.extend(sca_findings)
                except Exception as exc:
                    logger.error("Dependency analyzer failed on file", extra={"file": file_inv.file_path, "error": str(exc)})
                    scan_errors.append(
                        ScanErrorEntry(
                            file_path=file_inv.file_path,
                            error_type=f"DependencyAnalyzer.{type(exc).__name__}",
                            message=str(exc)
                        )
                    )

            # Dataflow taint analysis
            if file_inv.language == "python":
                try:
                    all_findings.extend(
                        self.dataflow_engine.analyze_file(file_inv.file_path, content)
                    )
                except Exception as exc:
                    logger.error("Dataflow engine failed on file", extra={"file": file_inv.file_path, "error": str(exc)})
                    scan_errors.append(
                        ScanErrorEntry(
                            file_path=file_inv.file_path,
                            error_type=f"DataFlowEngine.{type(exc).__name__}",
                            message=str(exc)
                        )
                    )

        # 3. Context-wide SAST analysis
        try:
            all_findings.extend(self.sast_engine.analyze_context(context))
        except Exception as exc:
            logger.error("SAST engine context analysis failed", extra={"error": str(exc)})
            scan_errors.append(
                ScanErrorEntry(
                    file_path="<context>",
                    error_type=f"SASTEngine.{type(exc).__name__}",
                    message=str(exc)
                )
            )

        # 4. Filter suppressions (inline comments & baseline)
        all_findings = self._filter_suppressions(path, all_findings)

        # 5. Correlate findings & compute risk
        correlated = self.correlator.correlate(all_findings)
        risk = self.risk_engine.calculate_risk(snapshot.repository_id, all_findings, asset_criticality)

        duration = round(time.monotonic() - start_time, 3)
        status = "PARTIAL" if scan_errors else "COMPLETED"

        logger.info(
            "Scan finished",
            extra={
                "scan_id": scan_id,
                "status": status,
                "findings": len(all_findings),
                "errors": len(scan_errors),
                "duration_seconds": duration
            }
        )

        return ScanResult(
            scan_id=scan_id,
            repository_id=snapshot.repository_id,
            status=status,
            scanner_version=self.version,
            findings=all_findings,
            findings_count=len(all_findings),
            dependencies=all_dependencies,
            correlated_findings=correlated,
            risk_assessment=risk,
            scan_errors=scan_errors,
            scanned_files_count=len(snapshot.files),
            duration_seconds=duration
        )
