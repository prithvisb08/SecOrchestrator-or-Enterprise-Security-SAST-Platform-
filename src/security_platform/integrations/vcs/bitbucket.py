import logging
from typing import Any

import httpx

from security_platform.integrations.vcs.base import (
    CheckRunReport,
    PRContext,
    VCSProvider,
)

logger = logging.getLogger("security_platform.integrations.bitbucket")


class BitbucketProvider(VCSProvider):
    """Bitbucket Cloud integration handling pull request webhooks, commit statuses, and comments."""

    def __init__(
        self,
        token: str | None = None,
        http_client: httpx.Client | None = None,
        api_base_url: str = "https://api.bitbucket.org/2.0",
    ) -> None:
        self.token = token or "mock_bitbucket_token"
        self.api_base_url = api_base_url.rstrip("/")
        self.client = http_client or httpx.Client(timeout=15.0)

    def parse_webhook_event(
        self,
        headers: dict[str, str],
        payload: dict[str, Any]
    ) -> PRContext | None:
        event = headers.get("x-event-key", "")
        if not event.startswith("pullrequest:"):
            return None

        action = event.split(":")[-1]  # "created", "updated"
        if action not in ("created", "updated"):
            return None

        pr_data = payload.get("pullrequest", {})
        repo_data = payload.get("repository", {})

        repo_name = repo_data.get("full_name", "")
        pr_number = pr_data.get("id", 0)
        commit_sha = pr_data.get("source", {}).get("commit", {}).get("hash", "")
        base_branch = pr_data.get("destination", {}).get("branch", {}).get("name", "main")
        head_branch = pr_data.get("source", {}).get("branch", {}).get("name", "")
        sender = payload.get("actor", {}).get("nickname", "")

        return PRContext(
            provider="bitbucket",
            repo_name=repo_name,
            pr_number=pr_number,
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
        """Sets a commit build status in Bitbucket."""
        status_state = "SUCCESSFUL" if report.conclusion == "success" else "FAILED"
        url = f"{self.api_base_url}/repositories/{context.repo_name}/commit/{context.commit_sha}/statuses/build"
        headers = {"Authorization": f"Bearer {self.token}"}

        payload = {
            "key": "secorchestrator-sast",
            "state": status_state,
            "name": report.name,
            "description": report.summary[:255],
            "url": "https://secorchestrator.internal/scans",
        }

        try:
            resp = self.client.post(url, json=payload, headers=headers)
            if resp.status_code in (200, 201):
                return "bitbucket_status_ok"
            return "bitbucket_status_failed"
        except Exception as exc:
            logger.error("Bitbucket commit status failed: %s", exc)
            return "bitbucket_error"

    def post_or_update_summary_comment(
        self,
        context: PRContext,
        summary_markdown: str,
        marker: str = "<!-- secorchestrator-pr-summary -->"
    ) -> str:
        """Posts or updates a comment on the Bitbucket pull request."""
        comments_url = f"{self.api_base_url}/repositories/{context.repo_name}/pullrequests/{context.pr_number}/comments"
        headers = {"Authorization": f"Bearer {self.token}"}
        full_body = f"{marker}\n{summary_markdown}"

        try:
            resp = self.client.get(comments_url, headers=headers)
            if resp.status_code == 200:
                comments = resp.json().get("values", [])
                for comment in comments:
                    content_raw = comment.get("content", {}).get("raw", "")
                    if marker in content_raw:
                        comment_id = comment.get("id")
                        update_url = f"{comments_url}/{comment_id}"
                        patch_resp = self.client.put(
                            update_url,
                            json={"content": {"raw": full_body}},
                            headers=headers
                        )
                        if patch_resp.status_code == 200:
                            return f"updated_{comment_id}"

            create_resp = self.client.post(
                comments_url,
                json={"content": {"raw": full_body}},
                headers=headers
            )
            if create_resp.status_code in (200, 201):
                return f"created_{create_resp.json().get('id')}"
            return "bitbucket_comment_failed"
        except Exception as exc:
            logger.error("Bitbucket comment error: %s", exc)
            return "bitbucket_error"

    def upload_sarif(
        self,
        context: PRContext,
        sarif_json: str
    ) -> bool:
        return True
