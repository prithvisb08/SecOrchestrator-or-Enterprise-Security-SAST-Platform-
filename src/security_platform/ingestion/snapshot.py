from pathlib import Path

from security_platform.ingestion.discovery import ProjectDiscovery
from security_platform.ingestion.loaders import LocalLoader
from security_platform.ingestion.models import RepositorySnapshot


class RepositorySnapshotBuilder:
    def __init__(self, workspace_path: str | Path):
        self.workspace_path = Path(workspace_path)

    def build_snapshot(self, repository_id: str) -> RepositorySnapshot:
        loader = LocalLoader(str(self.workspace_path))
        discovery = ProjectDiscovery(loader)
        return discovery.build_snapshot(repository_id)
