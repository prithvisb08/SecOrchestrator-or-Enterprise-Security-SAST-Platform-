from datetime import UTC, datetime

from pydantic import BaseModel, Field


class Repository(BaseModel):
    repository_id: str
    repository_name: str
    source_type: str = Field(..., description="e.g., github, gitlab, local, archive")
    language: str | None = None
    commit_hash: str | None = None
    branch: str | None = None
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scanner_version: str
    metadata: dict[str, str] = Field(default_factory=dict)
