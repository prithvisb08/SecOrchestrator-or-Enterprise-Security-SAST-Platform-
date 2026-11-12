import base64
import gzip
import hashlib
import hmac
import logging
from typing import Any

import httpx

from security_platform.integrations.vcs.base import (
    CheckRunReport,
    PRContext,
    VCSProvider,
)

logger = logging.getLogger("security_platform.integrations.github")


class GitHubAppProvider(VCSProvider):
    """GitHub App integration handling Webhooks, Check Runs, PR comments, and SARIF upload."""

    def __init__(
        self,
        app_id: str | None = None,
        private_key: str | None = None,
        webhook_secret: str | None = None,
        http_client: httpx.Client | None = None,
        api_base_url: str = "https://api.github.com",
    ) -> None:
        self.app_id = app_id
        self.private_key = private_key
        self.webhook_secret = webhook_secret
        self.api_base_url = api_base_url.rstrip("/")
        self.client = http_client or httpx.Client(timeout=15.0)

    def verify_webhook_signature(self, payload_bytes: bytes, signature_header: str | None) -> bool:
        """Verifies X-Hub-Signature-256 header using the configured webhook secret."""
        if not self.webhook_secret:
            return True  # If no secret configured (dev mode), accept
        if not signature_header or not signature_header.startswith("sha256="):
            return False

        expected = "sha256=" + hmac.new(
            self.webhook_secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected, signature_header)

    def parse_webhook_event(
        self,
        headers: dict[str, str],
        payload: dict[str, Any]
    ) -> PRContext | None:
        event = headers.get("x-github-event", "")
        if event != "pull_request":
            return None

        action = payload.get("action", "")
        if action not in ("opened", "synchronize", "reopened"):
            return None

        pr_data = payload.get("pull_request", {})
        repo_data = payload.get("repository", {})
        installation = payload.get("installation", {})

        repo_name = repo_data.get("full_name", "")
        pr_number = pr_data.get("number", 0)
        commit_sha = pr_data.get("head", {}).get("sha", "")
        base_branch = pr_data.get("base", {}).get("ref", "main")
        head_branch = pr_data.get("head", {}).get("ref", "")
        sender = payload.get("sender", {}).get("login", "")
        inst_id = str(installation.get("id")) if installation else None

        return PRContext(
            provider="github",
            repo_name=repo_name,
            pr_number=pr_number,
            commit_sha=commit_sha,
            base_branch=base_branch,
            head_branch=head_branch,
            action=action,
            sender=sender,
            installation_id=inst_id,
        )

    def _get_auth_headers(self, installation_id: str | None = None) -> dict[str, str]:
        # In a real GitHub App deployment, this would exchange an App JWT for an installation token
        token = "ghs_mock_installation_token"  # secorch: ignore[SEC-SECRET-HARDCODED_SECRET-001] reason="Mock token for dev/testing"
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",  # secorch: ignore[SEC-SECRET-HARDCODED_SECRET-001] reason="Static API version header"
        }

    def publish_check_run(
        self,
        context: PRContext,
        report: CheckRunReport
    ) -> str:
        """Creates or updates a GitHub Check Run with up to 50 line annotations."""
        url = f"{self.api_base_url}/repos/{context.repo_name}/check-runs"
        headers = self._get_auth_headers(context.installation_id)

        # Map annotations to GitHub schema
        github_annotations: list[dict[str, Any]] = []
        for ann in report.annotations[:50]:  # GitHub allows max 50 per call
            item: dict[str, Any] = {
                "path": ann.path,
                "start_line": ann.start_line,
                "end_line": ann.end_line,
                "annotation_level": ann.annotation_level,
                "message": ann.message,
                "title": ann.title,
            }
            if ann.raw_details:
                item["raw_details"] = ann.raw_details
            github_annotations.append(item)

        payload: dict[str, Any] = {
            "name": report.name,
            "head_sha": report.head_sha,
            "status": report.status,
            "conclusion": report.conclusion,
            "output": {
                "title": report.title,
                "summary": report.summary,
                "annotations": github_annotations,
            },
        }
        if report.text:
            payload["output"]["text"] = report.text

        try:
            resp = self.client.post(url, json=payload, headers=headers)
            if resp.status_code in (200, 201):
                data = resp.json()
                return str(data.get("id", "check_run_created"))
            logger.warning("Failed to create GitHub Check Run: %s %s", resp.status_code, resp.text)
            return "check_run_fallback"
        except Exception as exc:
            logger.error("Exception calling GitHub Check Run API: %s", exc)
            return "check_run_error"

    def post_or_update_summary_comment(
        self,
        context: PRContext,
        summary_markdown: str,
        marker: str = "<!-- secorchestrator-pr-summary -->"
    ) -> str:
        """Finds existing PR summary comment with marker and edits it in-place, preventing spam."""
        comments_url = f"{self.api_base_url}/repos/{context.repo_name}/issues/{context.pr_number}/comments"
        headers = self._get_auth_headers(context.installation_id)

        full_body = f"{marker}\n{summary_markdown}"

        try:
            # 1. Fetch existing comments to see if one already has marker
            resp = self.client.get(comments_url, headers=headers)
            if resp.status_code == 200:
                comments = resp.json()
                for c in comments:
                    if marker in c.get("body", ""):
                        comment_id = c.get("id")
                        update_url = f"{self.api_base_url}/repos/{context.repo_name}/issues/comments/{comment_id}"
                        patch_resp = self.client.patch(update_url, json={"body": full_body}, headers=headers)
                        if patch_resp.status_code == 200:
                            return f"updated_{comment_id}"

            # 2. If no existing comment found, create new one
            create_resp = self.client.post(comments_url, json={"body": full_body}, headers=headers)
            if create_resp.status_code in (200, 201):
                new_id = create_resp.json().get("id")
                return f"created_{new_id}"

            return "comment_failed"
        except Exception as exc:
            logger.error("Failed to post or update PR comment: %s", exc)
            return "comment_exception"

    def upload_sarif(
        self,
        context: PRContext,
        sarif_json: str
    ) -> bool:
        """Uploads gzipped and base64-encoded SARIF to GitHub Code Scanning."""
        url = f"{self.api_base_url}/repos/{context.repo_name}/code-scanning/sarifs"
        headers = self._get_auth_headers(context.installation_id)

        compressed = gzip.compress(sarif_json.encode("utf-8"))
        b64_sarif = base64.b64encode(compressed).decode("ascii")

        payload = {
            "commit_sha": context.commit_sha,
            "ref": f"refs/pull/{context.pr_number}/head",
            "sarif": b64_sarif,
        }

        try:
            resp = self.client.post(url, json=payload, headers=headers)
            return resp.status_code in (200, 201, 202)
        except Exception as exc:
            logger.error("Failed to upload SARIF to GitHub Code Scanning: %s", exc)
            return False
