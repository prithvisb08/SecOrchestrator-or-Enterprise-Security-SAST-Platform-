import os
import tarfile
import tempfile
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path

from security_platform.core.errors import ArchiveSecurityError


class RepositoryLoader(ABC):
    @abstractmethod
    def get_workspace(self) -> Path:
        pass

    @abstractmethod
    def cleanup(self) -> None:
        pass


class LocalLoader(RepositoryLoader):
    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()

    def get_workspace(self) -> Path:
        return self.path

    def cleanup(self) -> None:
        pass


class ArchiveLoader(RepositoryLoader):
    MAX_EXTRACT_SIZE = 500 * 1024 * 1024  # 500 MB
    MAX_FILE_COUNT = 10_000  # Cap file count against inode exhaustion
    CHUNK_SIZE = 64 * 1024  # 64 KB read buffer

    def __init__(self, archive_path: str | Path, target_dir: str | Path | None = None):
        self.archive_path = Path(archive_path)
        if target_dir:
            self._temp_dir = None
            self._workspace = Path(target_dir).resolve()
            self._workspace.mkdir(parents=True, exist_ok=True)
        else:
            self._temp_dir = tempfile.TemporaryDirectory()
            self._workspace = Path(self._temp_dir.name).resolve()
        self._extract_securely()

    def _extract_securely(self) -> None:
        target_root = getattr(self, "_workspace", None)
        if target_root is None:
            if self._temp_dir is not None:
                target_root = Path(self._temp_dir.name).resolve()
            else:
                target_root = Path(tempfile.mkdtemp(prefix="secorch_archive_")).resolve()

        if tarfile.is_tarfile(self.archive_path):
            self._extract_tar(target_root)
        elif zipfile.is_zipfile(self.archive_path):
            self._extract_zip(target_root)
        else:
            raise ArchiveSecurityError(f"Unsupported or invalid archive format: {self.archive_path.name}")

    def _extract_zip(self, target_root: Path) -> None:
        current_size = 0
        file_count = 0

        with zipfile.ZipFile(self.archive_path, "r") as zip_ref:
            for member in zip_ref.infolist():
                file_count += 1
                if file_count > self.MAX_FILE_COUNT:
                    raise ArchiveSecurityError(
                        f"Exceeded maximum file count ({self.MAX_FILE_COUNT}) in archive"
                    )

                # 1. Reject symlinks / devices / FIFOs
                # UNIX file type is stored in upper 16 bits of external_attr
                unix_mode = member.external_attr >> 16
                if unix_mode and (unix_mode & 0o170000 == 0o120000):
                    raise ArchiveSecurityError(f"Symlinks are rejected for security: {member.filename}")
                if member.is_dir():
                    continue

                # 2. Strict Zip-Slip check: normalize and verify it's inside target_root
                norm_name = os.path.normpath(member.filename.replace("\\", "/"))
                dest_path = (target_root / norm_name).resolve()
                if not dest_path.is_relative_to(target_root) or dest_path == target_root:
                    raise ArchiveSecurityError(f"Path traversal / zip slip detected: {member.filename}")

                dest_path.parent.mkdir(parents=True, exist_ok=True)

                # 3. Stream decompression to measure actual extracted bytes (anti-zip bomb)
                with zip_ref.open(member) as src_file, open(dest_path, "wb") as dest_file:
                    while chunk := src_file.read(self.CHUNK_SIZE):
                        current_size += len(chunk)
                        if current_size > self.MAX_EXTRACT_SIZE:
                            raise ArchiveSecurityError(
                                f"Exceeded maximum extraction size limit ({self.MAX_EXTRACT_SIZE} bytes)"
                            )
                        dest_file.write(chunk)

    def _extract_tar(self, target_root: Path) -> None:
        with tarfile.open(self.archive_path, "r:*") as tar:
            file_count = 0
            total_size = 0

            for member in tar.getmembers():
                file_count += 1
                if file_count > self.MAX_FILE_COUNT:
                    raise ArchiveSecurityError(
                        f"Exceeded maximum file count ({self.MAX_FILE_COUNT}) in archive"
                    )

                # Reject symlinks and hardlinks
                if member.issym() or member.islnk():
                    raise ArchiveSecurityError(f"Symlinks are rejected for security: {member.name}")

                dest_path = (target_root / member.name).resolve()
                if not dest_path.is_relative_to(target_root):
                    raise ArchiveSecurityError(f"Path traversal detected in tar: {member.name}")

                total_size += member.size
                if total_size > self.MAX_EXTRACT_SIZE:
                    raise ArchiveSecurityError(
                        f"Exceeded maximum extraction size limit ({self.MAX_EXTRACT_SIZE} bytes)"
                    )

            # In Python 3.12+, filter="data" provides standard defense-in-depth
            try:
                tar.extractall(target_root, filter="data")
            except TypeError:
                # Fallback if filter not supported
                tar.extractall(target_root)

    def get_workspace(self) -> Path:
        return self._workspace

    def cleanup(self) -> None:
        if self._temp_dir:
            self._temp_dir.cleanup()
