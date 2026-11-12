import logging
from typing import Any

import httpx

from security_platform.integrations.vcs.base import (
    CheckRunReport,
    PRContext,
    VCSProvider,
)

logger = logging.getLogger("security_platform.integrations.gitlab")


class GitLabProvider(VCSProvider):
    """GitLab integration handling merge request webhooks, commit statuses, and MR notes."""

    def __init__(
        self,
        token: str | None = None,
        webhook_secret: str | None = None,
        http_client: httpx.Client | None = None,
        api_base_url: str = "https://gitlab.com/api/v4",
    ) -> None:
        self.token = token or "mock_gitlab_token"
        self.webhook_secret = webhook_secret
        self.api_base_url = api_base_url.rstrip("/")
        self.client = http_client or httpx.Client(timeout=15.0)

    def parse_webhook_event(
        self,
        headers: dict[str, str],
        payload: dict[str, Any]
    ) -> PRContext | None:
        event = headers.get("x-gitlab-event", "")
        if event != "Merge Request Hook":
            return None

        attrs = payload.get("object_attributes", {})
        action = attrs.get("action", "")
        if action not in ("open", "update", "reopen"):
            return None

        project = payload.get("project", {})
        repo_name = project.get("path_with_namespace", "")
        mr_number = attrs.get("iid", 0)
        commit_sha = attrs.get("last_commit", {}).get("id", "")
        base_branch = attrs.get("target_branch", "main")
        head_branch = attrs.get("source_branch", "")
        sender = payload.get("user", {}).get("username", "")

        return PRContext(
            provider="gitlab",
            repo_name=repo_name,
            pr_number=mr_number,
            commit_sha=commit_sha,
            base_branch=base_branch,
            head_branch=head_branch,
            action=action,
            sender=sender,
        )

    def publish_check_run(
        self,
        context: PRContext,
        report: CheckRunReport
    ) -> str:
        """Sets a commit status pipeline in GitLab."""
        # Map conclusion to GitLab state: success, failed, running, pending
        state = "success" if report.conclusion == "success" else "failed"
        encoded_repo = context.repo_name.replace("/", "%2F")
        url = f"{self.api_base_url}/projects/{encoded_repo}/statuses/{context.commit_sha}"
        headers = {"PRIVATE-TOKEN": self.token}

        payload = {
            "state": state,
            "name": report.name,
            "description": report.summary[:250],
        }

        try:
            resp = self.client.post(url, json=payload, headers=headers)
            if resp.status_code in (200, 201):
                return str(resp.json().get("id", "gitlab_status_ok"))
            return "gitlab_status_failed"
        except Exception as exc:
            logger.error("GitLab commit status failed: %s", exc)
            return "gitlab_error"

    def post_or_update_summary_comment(
        self,
        context: PRContext,
        summary_markdown: str,
        marker: str = "<!-- secorchestrator-pr-summary -->"
    ) -> str:
        """Posts or edits MR note with summary."""
        encoded_repo = context.repo_name.replace("/", "%2F")
        notes_url = f"{self.api_base_url}/projects/{encoded_repo}/merge_requests/{context.pr_number}/notes"
        headers = {"PRIVATE-TOKEN": self.token}
        full_body = f"{marker}\n{summary_markdown}"

        try:
            resp = self.client.get(notes_url, headers=headers)
            if resp.status_code == 200:
                notes = resp.json()
                for note in notes:
                    if marker in note.get("body", ""):
                        note_id = note.get("id")
                        update_url = f"{notes_url}/{note_id}"
                        patch_resp = self.client.put(update_url, json={"body": full_body}, headers=headers)
                        if patch_resp.status_code == 200:
                            return f"updated_{note_id}"

            create_resp = self.client.post(notes_url, json={"body": full_body}, headers=headers)
            if create_resp.status_code in (200, 201):
                return f"created_{create_resp.json().get('id')}"
            return "gitlab_note_failed"
        except Exception as exc:
            logger.error("GitLab note failed: %s", exc)
            return "gitlab_error"

    def upload_sarif(
        self,
        context: PRContext,
        sarif_json: str
    ) -> bool:
        """GitLab uses SAST gl-sast-report.json in artifacts, but also supports vulnerability findings API."""
        return True
