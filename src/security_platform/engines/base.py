import shutil
from abc import ABC, abstractmethod
from pathlib import Path

from security_platform.ingestion.models import RepositorySnapshot
from security_platform.models.finding import Finding


class Engine(ABC):
    """Protocol / base class for both native and external security scanning engines."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique engine identifier (e.g. 'bandit', 'semgrep', 'native_secrets')."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Engine version string."""
        pass

    @abstractmethod
    def supports(self, snapshot: RepositorySnapshot) -> bool:
        """Determines whether this engine is applicable for the given repository snapshot."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Checks if the underlying CLI tool or dependencies are available in the runtime environment."""
        pass

    @abstractmethod
    def run(self, workspace: Path, timeout_seconds: int = 60) -> list[Finding]:
        """
        Executes analysis against the target workspace directory and returns normalized findings.
        Must raise an exception or handle errors gracefully on execution failure.
        """
        pass


def is_binary_available(binary_name: str) -> bool:
    """Helper to verify if an executable exists on the system PATH."""
    return shutil.which(binary_name) is not None
