import json
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from security_platform.engines.base import Engine, is_binary_available
from security_platform.engines.secret_scanner import SecretScanner
from security_platform.enums.severity import Severity
from security_platform.ingestion.models import RepositorySnapshot
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class GitleaksEngine(Engine):
    @property
    def name(self) -> str:
        return "gitleaks"

    @property
    def version(self) -> str:
        return "8.18.2"

    def is_available(self) -> bool:
        return is_binary_available("gitleaks")

    def supports(self, snapshot: RepositorySnapshot) -> bool:
        return True  # Gitleaks can scan any repository or directory

    def parse_gitleaks_json(self, raw_json: str, workspace: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not raw_json.strip():
            return findings

        try:
            items: list[dict[str, Any]] = json.loads(raw_json)
        except json.JSONDecodeError:
            return findings

        for item in items:
            rule_id = item.get("RuleID", "generic-secret")
            desc = item.get("Description", "Secret detected by Gitleaks")
            file_path = item.get("File", "")
            try:
                rel_path = str(Path(file_path).relative_to(workspace))
            except ValueError:
                rel_path = file_path

            start_line = int(item.get("StartLine", 1))
            end_line = int(item.get("EndLine", start_line))
            raw_secret = item.get("Secret", "")

            # Compute salted hash and NEVER store raw secret
            token_hash = SecretScanner()._compute_salted_hash(raw_secret)
            fingerprint = f"rule:GITLEAKS-{rule_id}:hash:{token_hash[:16]}"

            # Redact secret in snippet
            match_line = item.get("Match", "")
            if raw_secret and raw_secret in match_line:
                redacted_snippet = match_line.replace(raw_secret, "[REDACTED_SECRET]")
            else:
                redacted_snippet = "[REDACTED_SECRET]"

            finding = Finding(
                finding_id=str(uuid.uuid4()),
                rule_id=f"GITLEAKS-{rule_id}",
                category=Category.SECRETS,
                vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
                title=f"Gitleaks: {desc}",
                description=f"Secret identified by Gitleaks pattern '{rule_id}'.",
                severity=Severity.CRITICAL if "key" in rule_id.lower() or "token" in rule_id.lower() else Severity.HIGH,
                confidence=0.95,
                location=SourceLocation(file_path=rel_path, start_line=start_line, end_line=end_line),
                code_snippet=redacted_snippet,
                evidence=f"Gitleaks matched rule {rule_id} (fingerprint: {token_hash[:12]}).",
                root_cause="Hardcoded credential identified in repository history or working files.",
                recommendation="Immediately revoke the secret and replace with environment configuration.",
                scanner_version=self.version,
                metadata={"secret_hash": token_hash, "fingerprint": fingerprint, "engine": "gitleaks"},
                fingerprint=fingerprint
            )
            findings.append(finding)

        return findings

    def run(self, workspace: Path, timeout_seconds: int = 60) -> list[Finding]:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as report_file:
            report_path = report_file.name

        try:
            cmd = [
                "gitleaks", "dir", str(workspace),
                "--report-format", "json",
                "--report-path", report_path,
                "--no-banner",
            ]
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False  # Gitleaks returns exit code 1 when leaks are detected
            )
            content = Path(report_path).read_text(encoding="utf-8", errors="ignore")
            return self.parse_gitleaks_json(content, workspace)
        finally:
            p = Path(report_path)
            if p.exists():
                p.unlink()
