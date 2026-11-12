import concurrent.futures
from pathlib import Path

from security_platform.core.logging import logger
from security_platform.engines.adapters.bandit import BanditEngine
from security_platform.engines.adapters.checkov import CheckovEngine
from security_platform.engines.adapters.gitleaks import GitleaksEngine
from security_platform.engines.adapters.osv import OSVScannerEngine
from security_platform.engines.adapters.semgrep import SemgrepEngine
from security_platform.engines.adapters.trivy import TrivyEngine
from security_platform.engines.base import Engine
from security_platform.ingestion.models import RepositorySnapshot
from security_platform.models.finding import Finding


class EngineRegistry:
    """Registry and parallel executor for external and native analysis engines."""

    def __init__(self) -> None:
        self._engines: dict[str, Engine] = {}

    def register(self, engine: Engine) -> None:
        self._engines[engine.name] = engine

    def get(self, name: str) -> Engine | None:
        return self._engines.get(name)

    def list_engines(self) -> list[Engine]:
        return list(self._engines.values())

    def get_supported_available_engines(self, snapshot: RepositorySnapshot) -> list[Engine]:
        """Returns engines that are both installed in the system and applicable for the snapshot."""
        return [
            eng for eng in self._engines.values()
            if eng.is_available() and eng.supports(snapshot)
        ]

    def run_engine_safe(
        self, engine: Engine, workspace: Path, timeout_seconds: int = 60
    ) -> tuple[str, list[Finding], Exception | None]:
        """Executes a single engine wrapped in exception and timeout safeguards."""
        try:
            findings = engine.run(workspace, timeout_seconds=timeout_seconds)
            return engine.name, findings, None
        except Exception as exc:
            logger.error("Engine execution failed", extra={"engine": engine.name, "error": str(exc)})
            return engine.name, [], exc

    def run_parallel(
        self,
        snapshot: RepositorySnapshot,
        workspace: Path,
        timeout_seconds: int = 60,
        max_workers: int = 4
    ) -> tuple[list[Finding], list[tuple[str, Exception]]]:
        """Runs applicable engines in parallel threads, aggregating findings and partial errors."""
        engines_to_run = self.get_supported_available_engines(snapshot)
        if not engines_to_run:
            return [], []

        all_findings: list[Finding] = []
        engine_errors: list[tuple[str, Exception]] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_engine = {
                executor.submit(self.run_engine_safe, eng, workspace, timeout_seconds): eng
                for eng in engines_to_run
            }

            for future in concurrent.futures.as_completed(future_to_engine):
                engine_name, findings, error = future.result()
                if error:
                    engine_errors.append((engine_name, error))
                else:
                    all_findings.extend(findings)

        return all_findings, engine_errors


def create_default_registry() -> EngineRegistry:
    """Instantiates registry pre-populated with standard supported external engines."""
    registry = EngineRegistry()
    registry.register(BanditEngine())
    registry.register(SemgrepEngine())
    registry.register(GitleaksEngine())
    registry.register(TrivyEngine())
    registry.register(OSVScannerEngine())
    registry.register(CheckovEngine())
    return registry
