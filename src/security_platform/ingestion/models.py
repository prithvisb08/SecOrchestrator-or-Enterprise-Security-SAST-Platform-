from datetime import UTC, datetime

from pydantic import BaseModel, Field


class FileInventory(BaseModel):
    file_path: str
    size_bytes: int
    sha256_hash: str
    language: str | None = None
    is_manifest: bool = False

class RepositorySnapshot(BaseModel):
    repository_id: str
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    total_size_bytes: int = 0
    total_files: int = 0
    ignored_files_count: int = 0
    language_statistics: dict[str, int] = Field(default_factory=dict)
    manifests_detected: list[str] = Field(default_factory=list)
    files: list[FileInventory] = Field(default_factory=list)
