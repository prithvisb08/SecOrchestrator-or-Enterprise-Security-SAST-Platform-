from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class CheckAnnotation(BaseModel):
    path: str
    start_line: int
    end_line: int
    annotation_level: str = "warning"  # "notice", "warning", "failure"
    title: str
    message: str
    raw_details: str | None = None


class CheckRunReport(BaseModel):
    name: str = "SecOrchestrator SAST & Security Gate"
    head_sha: str
    status: str = "completed"  # "queued", "in_progress", "completed"
    conclusion: str = "success"  # "success", "failure", "neutral"
    title: str
    summary: str
    text: str | None = None
    annotations: list[CheckAnnotation] = Field(default_factory=list)


class PRContext(BaseModel):
    provider: str  # "github", "gitlab", "bitbucket"
    repo_name: str
    pr_number: int
    commit_sha: str
    base_branch: str
    head_branch: str
    changed_files: list[str] = Field(default_factory=list)
    action: str = "opened"  # "opened", "synchronize", "reopened"
    sender: str = ""
    installation_id: str | None = None


class VCSProvider(ABC):
    """Abstract interface for Version Control System platform integrations."""

    @abstractmethod
    def parse_webhook_event(
        self,
        headers: dict[str, str],
        payload: dict[str, Any]
    ) -> PRContext | None:
        """Parses an incoming platform webhook and extracts PR context if applicable."""
        pass

    @abstractmethod
    def publish_check_run(
        self,
        context: PRContext,
        report: CheckRunReport
    ) -> str:
        """Publishes or updates a commit check/status run with line annotations."""
        pass

    @abstractmethod
    def post_or_update_summary_comment(
        self,
        context: PRContext,
        summary_markdown: str,
        marker: str = "<!-- secorchestrator-pr-summary -->"
    ) -> str:
        """Posts a PR comment or updates existing comment in-place if marker is present."""
        pass

    @abstractmethod
    def upload_sarif(
        self,
        context: PRContext,
        sarif_json: str
    ) -> bool:
        """Uploads SARIF report to the platform's native code security scanning engine."""
        pass
