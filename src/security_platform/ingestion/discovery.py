import hashlib
import os
from pathlib import Path

from security_platform.ingestion.engines import IgnoreRuleEngine, LanguageDetector
from security_platform.ingestion.loaders import RepositoryLoader
from security_platform.ingestion.models import FileInventory, RepositorySnapshot


class ProjectDiscovery:
    def __init__(self, loader: RepositoryLoader):
        self.loader = loader
        self.ignore_engine = IgnoreRuleEngine()

    def _hash_file(self, path: Path) -> str:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def build_snapshot(self, repo_id: str) -> RepositorySnapshot:
        workspace = self.loader.get_workspace()
        snapshot = RepositorySnapshot(repository_id=repo_id)

        if workspace.is_file():
            size = workspace.stat().st_size
            lang = LanguageDetector.detect_language(workspace)
            is_manifest = LanguageDetector.is_manifest(workspace)
            inventory = FileInventory(
                file_path=str(workspace),
                size_bytes=size,
                sha256_hash=self._hash_file(workspace),
                language=lang,
                is_manifest=is_manifest
            )
            snapshot.files.append(inventory)
            snapshot.total_files = 1
            snapshot.total_size_bytes = size
            if lang:
                snapshot.language_statistics[lang] = 1
            if is_manifest:
                snapshot.manifests_detected.append(str(workspace))
            return snapshot

        for root, dirs, files in os.walk(workspace):
            # Prune ignored directories immediately to save time
            dirs[:] = [d for d in dirs if not self.ignore_engine.should_ignore(Path(root) / d)]

            for file in files:
                file_path = Path(root) / file
                if self.ignore_engine.should_ignore(file_path):
                    snapshot.ignored_files_count += 1
                    continue

                rel_path = str(file_path.relative_to(workspace))
                size = file_path.stat().st_size
                lang = LanguageDetector.detect_language(file_path)
                is_manifest = LanguageDetector.is_manifest(file_path)

                inventory = FileInventory(
                    file_path=rel_path,
                    size_bytes=size,
                    sha256_hash=self._hash_file(file_path),
                    language=lang,
                    is_manifest=is_manifest
                )

                snapshot.files.append(inventory)
                snapshot.total_files += 1
                snapshot.total_size_bytes += size
                if lang:
                    snapshot.language_statistics[lang] = snapshot.language_statistics.get(lang, 0) + 1
                if is_manifest:
                    snapshot.manifests_detected.append(rel_path)

        return snapshot
