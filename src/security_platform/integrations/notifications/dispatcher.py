import logging
from typing import Any

import httpx
from pydantic import BaseModel, Field

from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding

logger = logging.getLogger("security_platform.integrations.notifications")


class NotificationPayload(BaseModel):
    repository: str
    scan_id: str
    risk_score: float
    gate_passed: bool
    findings: list[Finding] = Field(default_factory=list)
    dashboard_url: str = "https://secorchestrator.internal/scans"


class SlackNotifier:
    """Dispatches Slack Block Kit alerts for critical security events."""

    def __init__(self, webhook_url: str | None = None, http_client: httpx.Client | None = None) -> None:
        self.webhook_url = webhook_url
        self.client = http_client or httpx.Client(timeout=10.0)

    def format_blocks(self, payload: NotificationPayload) -> dict[str, Any]:
        critical_count = sum(1 for f in payload.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in payload.findings if f.severity == Severity.HIGH)
        status_emoji = "✅" if payload.gate_passed else "🚨"

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} SecOrchestrator Scan Alert: {payload.repository}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Repository:*\n`{payload.repository}`"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n*{payload.risk_score:.1f} / 10.0*"},
                    {"type": "mrkdwn", "text": f"*Gate Status:*\n{'*PASSED*' if payload.gate_passed else '*BLOCKED*'}"},
                    {"type": "mrkdwn", "text": f"*Critical / High:*\n*{critical_count}* / *{high_count}*"},
                ],
            },
            {"type": "divider"},
        ]

        # Top critical findings
        for f in payload.findings[:5]:
            sev_icon = "🔴" if f.severity == Severity.CRITICAL else "🟠"
            loc = f"{f.location.file_path}:{f.location.start_line}"
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{sev_icon} *{f.severity.value}*: *{f.title}*\n`{loc}`\n>{f.description}",
                },
            })

        return {"blocks": blocks}

    def send(self, payload: NotificationPayload) -> bool:
        if not self.webhook_url:
            return False
        body = self.format_blocks(payload)
        try:
            resp = self.client.post(self.webhook_url, json=body)
            return resp.status_code in (200, 204)
        except Exception as exc:
            logger.error("Slack notification failed: %s", exc)
            return False


class TeamsNotifier:
    """Dispatches Microsoft Teams Connector cards for security gate alerts."""

    def __init__(self, webhook_url: str | None = None, http_client: httpx.Client | None = None) -> None:
        self.webhook_url = webhook_url
        self.client = http_client or httpx.Client(timeout=10.0)

    def format_card(self, payload: NotificationPayload) -> dict[str, Any]:
        theme_color = "28A745" if payload.gate_passed else "D9534F"
        critical_count = sum(1 for f in payload.findings if f.severity == Severity.CRITICAL)

        card: dict[str, Any] = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": f"SecOrchestrator scan for {payload.repository}",
            "sections": [
                {
                    "activityTitle": f"SecOrchestrator Scan: {payload.repository}",
                    "activitySubtitle": f"Scan ID: {payload.scan_id}",
                    "facts": [
                        {"name": "Status", "value": "PASSED" if payload.gate_passed else "FAILED / BLOCKED"},
                        {"name": "Risk Score", "value": f"{payload.risk_score:.1f}"},
                        {"name": "Critical Findings", "value": str(critical_count)},
                        {"name": "Total Findings", "value": str(len(payload.findings))},
                    ],
                    "markdown": True,
                }
            ],
            "potentialAction": [
                {
                    "@type": "OpenUri",
                    "name": "View in SecOrchestrator",
                    "targets": [{"os": "default", "uri": f"{payload.dashboard_url}/{payload.scan_id}"}],
                }
            ],
        }
        return card

    def send(self, payload: NotificationPayload) -> bool:
        if not self.webhook_url:
            return False
        card = self.format_card(payload)
        try:
            resp = self.client.post(self.webhook_url, json=card)
            return resp.status_code in (200, 204)
        except Exception as exc:
            logger.error("Teams notification failed: %s", exc)
            return False


class JiraNotifier:
    """Generates and creates Jira issues for Critical/High security findings."""

    def __init__(
        self,
        jira_base_url: str | None = None,
        email: str | None = None,
        api_token: str | None = None,
        project_key: str = "SEC",
        http_client: httpx.Client | None = None,
    ) -> None:
        self.jira_base_url = jira_base_url.rstrip("/") if jira_base_url else None
        self.email = email
        self.api_token = api_token
        self.project_key = project_key
        self.client = http_client or httpx.Client(timeout=10.0)

    def format_issue_payload(self, finding: Finding, repo: str) -> dict[str, Any]:
        priority = "Highest" if finding.severity == Severity.CRITICAL else "High"
        summary = f"[SecOrchestrator] {finding.severity.value}: {finding.title} in {finding.location.file_path}"
        description = (
            f"*Repository:* {repo}\n"
            f"*File:* {finding.location.file_path}:{finding.location.start_line}\n"
            f"*Vulnerability:* {finding.vulnerability_type.value}\n"
            f"*Rule ID:* {finding.rule_id}\n\n"
            f"*Description:*\n{finding.description}\n\n"
            f"*Remediation Guidance:*\n{finding.recommendation or 'Please sanitize input at boundary.'}"
        )

        return {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary[:250],
                "description": description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority},
                "labels": ["security", "sast", finding.category.value.lower()],
            }
        }

    def create_issue_for_finding(self, finding: Finding, repo: str) -> str | None:
        if not self.jira_base_url or not self.email or not self.api_token:
            return None

        url = f"{self.jira_base_url}/rest/api/2/issue"
        auth = (self.email, self.api_token)
        payload = self.format_issue_payload(finding, repo)

        try:
            resp = self.client.post(url, json=payload, auth=auth)
            if resp.status_code in (200, 201):
                data = resp.json()
                return str(data.get("key"))
            logger.warning("Failed to create Jira issue: %s %s", resp.status_code, resp.text)
            return None
        except Exception as exc:
            logger.error("Jira issue creation error: %s", exc)
            return None


class NotificationRouter:
    """Evaluates notification routing rules and dispatches to appropriate channels."""

    def __init__(
        self,
        slack: SlackNotifier | None = None,
        teams: TeamsNotifier | None = None,
        jira: JiraNotifier | None = None,
    ) -> None:
        self.slack = slack
        self.teams = teams
        self.jira = jira

    def dispatch_scan_alert(self, payload: NotificationPayload) -> dict[str, Any]:
        results: dict[str, Any] = {"slack": False, "teams": False, "jira_tickets": []}

        # Notify chat if gate failed or criticals exist
        has_critical = any(f.severity == Severity.CRITICAL for f in payload.findings)
        if not payload.gate_passed or has_critical:
            if self.slack:
                results["slack"] = self.slack.send(payload)
            if self.teams:
                results["teams"] = self.teams.send(payload)

        # File Jira tickets for CRITICAL findings
        if self.jira and has_critical:
            for f in payload.findings:
                if f.severity == Severity.CRITICAL:
                    ticket_key = self.jira.create_issue_for_finding(f, payload.repository)
                    if ticket_key:
                        results["jira_tickets"].append(ticket_key)

        return results
