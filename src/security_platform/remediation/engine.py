from pathlib import Path

from pydantic import BaseModel

from security_platform.models.finding import Finding
from security_platform.remediation.rewriter import ASTRewriter


class RemediationResult(BaseModel):
    file_path: str
    fixes_applied: int
    original_content: str
    patched_content: str

class RemediationEngine:
    """Orchestrates automated code fixes across repository files based on scan findings."""

    def __init__(self) -> None:
        self.rewriter = ASTRewriter()

    def apply_fixes_to_file(self, file_path: Path, findings: list[Finding]) -> RemediationResult | None:
        if not file_path.exists() or not file_path.suffix == ".py":
            return None

        original_content = file_path.read_text(encoding="utf-8")
        patched_content, fixes_count = self.rewriter.fix_python_code(original_content)

        if fixes_count > 0:
            file_path.write_text(patched_content, encoding="utf-8")
            return RemediationResult(
                file_path=str(file_path),
                fixes_applied=fixes_count,
                original_content=original_content,
                patched_content=patched_content
            )

        return None
