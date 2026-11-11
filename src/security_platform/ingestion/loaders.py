import tempfile
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path


class RepositoryLoader(ABC):
    @abstractmethod
    def get_workspace(self) -> Path:
        pass

    @abstractmethod
    def cleanup(self) -> None:
        pass


class LocalLoader(RepositoryLoader):
    def __init__(self, path: str):
        self.path = Path(path).resolve()

    def get_workspace(self) -> Path:
        return self.path

    def cleanup(self) -> None:
        pass


class ArchiveLoader(RepositoryLoader):
    MAX_EXTRACT_SIZE = 500 * 1024 * 1024  # 500 MB

    def __init__(self, archive_path: str):
        self.archive_path = archive_path
        self._temp_dir = tempfile.TemporaryDirectory()
        self._extract_securely()

    def _extract_securely(self) -> None:
        current_size = 0
        with zipfile.ZipFile(self.archive_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                if member.filename.startswith('/') or '..' in member.filename:
                    raise ValueError("Path traversal detected in archive")
                current_size += member.file_size
                if current_size > self.MAX_EXTRACT_SIZE:
                    raise ValueError("Archive exceeds maximum extraction size limit")
                zip_ref.extract(member, self._temp_dir.name)

    def get_workspace(self) -> Path:
        return Path(self._temp_dir.name)

    def cleanup(self) -> None:
        self._temp_dir.cleanup()
