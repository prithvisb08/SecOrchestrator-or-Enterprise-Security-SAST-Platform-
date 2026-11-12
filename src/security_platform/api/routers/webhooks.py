import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

from security_platform.integrations.vcs.bitbucket import BitbucketProvider
from security_platform.integrations.vcs.github import GitHubAppProvider
from security_platform.integrations.vcs.gitlab import GitLabProvider

logger = logging.getLogger("security_platform.api.webhooks")
router = APIRouter(prefix="/api/v1/webhooks", tags=["Webhooks"])

github_provider = GitHubAppProvider()
gitlab_provider = GitLabProvider()
bitbucket_provider = BitbucketProvider()


@router.post("/github")
async def github_webhook(
    request: Request,
    x_github_event: str = Header(..., alias="x-github-event"),
    x_hub_signature_256: str | None = Header(None, alias="x-hub-signature-256"),
) -> dict[str, Any]:
    body_bytes = await request.body()
    if not github_provider.verify_webhook_signature(body_bytes, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = await request.json()
    headers = {"x-github-event": x_github_event}
    if x_hub_signature_256:
        headers["x-hub-signature-256"] = x_hub_signature_256

    context = github_provider.parse_webhook_event(headers, payload)
    if not context:
        return {"status": "ignored", "reason": "Not a monitored pull request event"}

    logger.info(
        "Received GitHub PR event",
        extra={"repo": context.repo_name, "pr": context.pr_number, "action": context.action},
    )

    return {
        "status": "accepted",
        "provider": "github",
        "repo": context.repo_name,
        "pr_number": context.pr_number,
        "commit_sha": context.commit_sha,
    }


@router.post("/gitlab")
async def gitlab_webhook(
    request: Request,
    x_gitlab_event: str = Header(..., alias="x-gitlab-event"),
    x_gitlab_token: str | None = Header(None, alias="x-gitlab-token"),
) -> dict[str, Any]:
    payload = await request.json()
    headers = {"x-gitlab-event": x_gitlab_event}
    if x_gitlab_token:
        headers["x-gitlab-token"] = x_gitlab_token

    context = gitlab_provider.parse_webhook_event(headers, payload)
    if not context:
        return {"status": "ignored", "reason": "Not a monitored merge request event"}

    return {
        "status": "accepted",
        "provider": "gitlab",
        "repo": context.repo_name,
        "mr_number": context.pr_number,
        "commit_sha": context.commit_sha,
    }


@router.post("/bitbucket")
async def bitbucket_webhook(
    request: Request,
    x_event_key: str = Header(..., alias="x-event-key"),
) -> dict[str, Any]:
    payload = await request.json()
    headers = {"x-event-key": x_event_key}

    context = bitbucket_provider.parse_webhook_event(headers, payload)
    if not context:
        return {"status": "ignored", "reason": "Not a monitored pull request event"}

    return {
        "status": "accepted",
        "provider": "bitbucket",
        "repo": context.repo_name,
        "pr_number": context.pr_number,
        "commit_sha": context.commit_sha,
    }
