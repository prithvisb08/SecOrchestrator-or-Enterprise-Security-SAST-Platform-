import hashlib
import hmac
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from security_platform.api.app import app
from security_platform.api.auth import Role, create_access_token
from security_platform.enums.severity import Severity
from security_platform.integrations.notifications.dispatcher import (
    JiraNotifier,
    NotificationPayload,
    NotificationRouter,
    SlackNotifier,
    TeamsNotifier,
)
from security_platform.integrations.vcs.base import (
    CheckAnnotation,
    CheckRunReport,
    PRContext,
)
from security_platform.integrations.vcs.bitbucket import BitbucketProvider
from security_platform.integrations.vcs.github import GitHubAppProvider
from security_platform.integrations.vcs.gitlab import GitLabProvider
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.remediation.rewriter import (
    LibCSTRewriter,
    LLMSuggestionEngine,
)
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


@pytest.fixture
def test_client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    token = create_access_token(user_id="admin-1", tenant_id="test-tenant", role=Role.ADMIN)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_finding():
    return Finding(
        rule_id="SEC-INJ-SQL-001",
        category=Category.SECURITY,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        title="SQL Injection in Login",
        description="Unsanitized user input formatted into SQL query",
        severity=Severity.CRITICAL,
        confidence=0.95,
        location=SourceLocation(file_path="app/auth.py", start_line=42, end_line=42),
        scanner_version="1.0.0",
        fingerprint="fp-sql-auth-42",
        recommendation="Use parameterized queries instead of f-strings",
    )


# ---------------------------------------------------------
# 1. LibCST Deterministic Auto-Remediation Tests
# ---------------------------------------------------------

def test_libcst_rewriter_preserves_comments_and_fixes_yaml_load():
    code = (
        "# Configuration loader\n"
        "import yaml\n"
        "data = yaml.load(user_input)  # Insecure call\n"
    )
    rewriter = LibCSTRewriter()
    fixed, count, reports = rewriter.fix_code(code)

    assert count == 1
    assert "# Configuration loader" in fixed
    assert "# Insecure call" in fixed
    assert "yaml.safe_load(user_input)" in fixed
    assert "yaml.load(" not in fixed
    assert reports[0].rule_id == "SEC-DESER-001"


def test_libcst_rewriter_upgrades_weak_hashes():
    code = (
        "import hashlib\n"
        "h1 = hashlib.md5(b'data')\n"
        "h2 = hashlib.sha1(b'data')\n"
        "h3 = hashlib.md5(b'data', usedforsecurity=False)\n"
    )
    rewriter = LibCSTRewriter()
    fixed, count, _ = rewriter.fix_code(code)

    assert count == 2
    assert "hashlib.sha256(b'data')" in fixed
    assert "hashlib.md5(b'data', usedforsecurity=False)" in fixed


def test_libcst_rewriter_disables_subprocess_shell_true():
    code = (
        "import subprocess\n"
        "subprocess.run(['ls', '-la'], shell=True)\n"
    )
    rewriter = LibCSTRewriter()
    fixed, count, _ = rewriter.fix_code(code)

    assert count == 1
    assert "shell=False" in fixed
    assert "shell=True" not in fixed


def test_libcst_rewriter_parameterizes_sql_fstring():
    code = (
        "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
    )
    rewriter = LibCSTRewriter()
    fixed, count, _ = rewriter.fix_code(code)

    assert count == 1
    assert "%s" in fixed
    assert "uid" in fixed


def test_libcst_unified_diff_and_llm_suggestions():
    orig = "import yaml\nyaml.load(data)\n"
    rewriter = LibCSTRewriter()
    fixed, count, _ = rewriter.fix_code(orig)
    diff = rewriter.generate_unified_diff(orig, fixed, filename="config.py")

    assert "--- a/config.py" in diff
    assert "+++ b/config.py" in diff
    assert "-yaml.load(data)" in diff
    assert "+yaml.safe_load(data)" in diff

    llm = LLMSuggestionEngine()
    sugg = llm.generate_suggestion(
        rule_id="SEC-SSRF-001",
        file_path="fetcher.py",
        line_number=10,
        code_context="requests.get(url)",
        vulnerability_type="SSRF",
    )
    assert sugg.is_llm_generated is True
    assert "never be auto-merged" in sugg.disclaimer.lower()


# ---------------------------------------------------------
# 2. GitHub App Provider Tests
# ---------------------------------------------------------

def test_github_app_webhook_verification():
    secret = "webhook_secret_key_123"
    payload = b'{"action": "opened"}'
    expected_sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    provider = GitHubAppProvider(webhook_secret=secret)
    assert provider.verify_webhook_signature(payload, expected_sig) is True
    assert provider.verify_webhook_signature(payload, "sha256=invalid") is False


def test_github_app_parse_pull_request_event():
    provider = GitHubAppProvider()
    headers = {"x-github-event": "pull_request"}
    payload = {
        "action": "opened",
        "pull_request": {
            "number": 101,
            "head": {"sha": "abc1234", "ref": "feat-branch"},
            "base": {"ref": "main"},
        },
        "repository": {"full_name": "acme/corp-app"},
        "sender": {"login": "dev-alice"},
        "installation": {"id": 998877},
    }

    ctx = provider.parse_webhook_event(headers, payload)
    assert ctx is not None
    assert ctx.provider == "github"
    assert ctx.repo_name == "acme/corp-app"
    assert ctx.pr_number == 101
    assert ctx.commit_sha == "abc1234"
    assert ctx.installation_id == "998877"


def test_github_app_check_run_creation():
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"id": 556677}
    mock_client.post.return_value = mock_resp

    provider = GitHubAppProvider(http_client=mock_client)
    ctx = PRContext(
        provider="github",
        repo_name="acme/corp-app",
        pr_number=101,
        commit_sha="abc1234",
        base_branch="main",
        head_branch="feat",
    )
    report = CheckRunReport(
        head_sha="abc1234",
        conclusion="failure",
        title="Security Gate Failed",
        summary="1 Critical finding detected",
        annotations=[
            CheckAnnotation(
                path="app/main.py",
                start_line=10,
                end_line=10,
                annotation_level="failure",
                title="SQL Injection",
                message="Unsanitized parameter",
            )
        ],
    )

    check_id = provider.publish_check_run(ctx, report)
    assert check_id == "556677"
    assert mock_client.post.called
    called_payload = mock_client.post.call_args[1]["json"]
    assert called_payload["conclusion"] == "failure"
    assert len(called_payload["output"]["annotations"]) == 1


def test_github_app_summary_comment_in_place_update():
    mock_client = MagicMock()

    # 1. First call: Existing comment with marker found -> should update in-place (PATCH)
    mock_get = MagicMock()
    mock_get.status_code = 200
    mock_get.json.return_value = [
        {"id": 4321, "body": "<!-- secorchestrator-pr-summary --> Old scan summary"}
    ]
    mock_patch = MagicMock()
    mock_patch.status_code = 200

    mock_client.get.return_value = mock_get
    mock_client.patch.return_value = mock_patch

    provider = GitHubAppProvider(http_client=mock_client)
    ctx = PRContext(
        provider="github",
        repo_name="acme/corp-app",
        pr_number=101,
        commit_sha="abc1234",
        base_branch="main",
        head_branch="feat",
    )

    res = provider.post_or_update_summary_comment(ctx, "### New Summary")
    assert res == "updated_4321"
    assert mock_client.patch.called


# ---------------------------------------------------------
# 3. GitLab & Bitbucket Adapters
# ---------------------------------------------------------

def test_gitlab_and_bitbucket_adapters():
    # GitLab
    gl = GitLabProvider()
    gl_headers = {"x-gitlab-event": "Merge Request Hook"}
    gl_payload = {
        "object_attributes": {
            "action": "open",
            "iid": 42,
            "last_commit": {"id": "c1"},
            "target_branch": "main",
            "source_branch": "patch",
        },
        "project": {"path_with_namespace": "group/project"},
    }
    gl_ctx = gl.parse_webhook_event(gl_headers, gl_payload)
    assert gl_ctx is not None
    assert gl_ctx.provider == "gitlab"
    assert gl_ctx.pr_number == 42

    # Bitbucket
    bb = BitbucketProvider()
    bb_headers = {"x-event-key": "pullrequest:created"}
    bb_payload = {
        "pullrequest": {
            "id": 99,
            "source": {"commit": {"hash": "h1"}, "branch": {"name": "feature"}},
            "destination": {"branch": {"name": "main"}},
        },
        "repository": {"full_name": "workspace/repo"},
    }
    bb_ctx = bb.parse_webhook_event(bb_headers, bb_payload)
    assert bb_ctx is not None
    assert bb_ctx.provider == "bitbucket"
    assert bb_ctx.pr_number == 99


# ---------------------------------------------------------
# 4. Notification Dispatchers (Slack, Teams, Jira)
# ---------------------------------------------------------

def test_notification_dispatchers(sample_finding):
    payload = NotificationPayload(
        repository="org/payments",
        scan_id="scan-xyz-123",
        risk_score=9.5,
        gate_passed=False,
        findings=[sample_finding],
    )

    # Slack Block Kit formatting
    slack = SlackNotifier()
    slack_blocks = slack.format_blocks(payload)
    assert len(slack_blocks["blocks"]) >= 3
    assert "🚨" in slack_blocks["blocks"][0]["text"]["text"]

    # Teams Connector Card formatting
    teams = TeamsNotifier()
    teams_card = teams.format_card(payload)
    assert teams_card["themeColor"] == "D9534F"

    # Jira Issue payload formatting
    jira = JiraNotifier(project_key="SEC")
    jira_issue = jira.format_issue_payload(sample_finding, "org/payments")
    assert jira_issue["fields"]["project"]["key"] == "SEC"
    assert jira_issue["fields"]["priority"]["name"] == "Highest"

    # Router logic
    mock_slack = MagicMock()
    mock_slack.send.return_value = True
    mock_jira = MagicMock()
    mock_jira.create_issue_for_finding.return_value = "SEC-404"

    router = NotificationRouter(slack=mock_slack, jira=mock_jira)
    dispatch_res = router.dispatch_scan_alert(payload)

    assert dispatch_res["slack"] is True
    assert "SEC-404" in dispatch_res["jira_tickets"]


# ---------------------------------------------------------
# 5. API Endpoints: Webhooks & Web UI
# ---------------------------------------------------------

def test_webhooks_api_endpoint(test_client):
    body = {
        "action": "opened",
        "pull_request": {
            "number": 55,
            "head": {"sha": "sha55", "ref": "fix"},
            "base": {"ref": "main"},
        },
        "repository": {"full_name": "acme/repo"},
    }
    resp = test_client.post(
        "/api/v1/webhooks/github",
        json=body,
        headers={"x-github-event": "pull_request"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted"


def test_ui_remediation_preview_endpoint(test_client, admin_headers):
    code = "import yaml\nres = yaml.load(data)\n"
    resp = test_client.post(
        "/api/v1/ui/remediation/preview",
        json={"source_code": code, "file_name": "service.py"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["fixes_applied"] == 1
    assert "yaml.safe_load" in data["patched_code"]
    assert "--- a/service.py" in data["git_diff"]
