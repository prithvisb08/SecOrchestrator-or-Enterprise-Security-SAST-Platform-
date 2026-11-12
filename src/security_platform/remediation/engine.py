from pathlib import Path

from pydantic import BaseModel

from security_platform.models.finding import Finding
from security_platform.remediation.rewriter import FixReport, LibCSTRewriter


class RemediationResult(BaseModel):
    file_path: str
    fixes_applied: int
    original_content: str
    patched_content: str
    git_patch: str = ""
    reports: list[FixReport] = []


class RemediationEngine:
    """Orchestrates automated code fixes across repository files based on scan findings."""

    def __init__(self) -> None:
        self.rewriter = LibCSTRewriter()

    def apply_fixes_to_file(
        self,
        file_path: Path,
        findings: list[Finding] | None = None,
        dry_run: bool = False,
    ) -> RemediationResult | None:
        if not file_path.exists() or not file_path.suffix == ".py":
            return None

        original_content = file_path.read_text(encoding="utf-8")
        patched_content, fixes_count, reports = self.rewriter.fix_code(original_content)

        if fixes_count > 0:
            if not dry_run:
                file_path.write_text(patched_content, encoding="utf-8")

            patch = self.rewriter.generate_unified_diff(
                original_content, patched_content, filename=file_path.name
            )

            return RemediationResult(
                file_path=str(file_path),
                fixes_applied=fixes_count,
                original_content=original_content,
                patched_content=patched_content,
                git_patch=patch,
                reports=reports,
            )

        return None

    def scan_and_remediate_directory(
        self,
        directory: Path,
        findings: list[Finding] | None = None,
        dry_run: bool = False,
    ) -> list[RemediationResult]:
        """Iterates over Python files in directory and applies fixes."""
        results: list[RemediationResult] = []
        for py_file in directory.rglob("*.py"):
            res = self.apply_fixes_to_file(py_file, findings=findings, dry_run=dry_run)
            if res:
                results.append(res)
        return results
