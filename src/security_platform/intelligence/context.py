from pathlib import Path

from security_platform.ingestion.models import RepositorySnapshot
from security_platform.intelligence.models import CallNode, ClassNode, FunctionNode, ImportNode
from security_platform.intelligence.parser import CodeParser


class AnalyzerContext:
    def __init__(self, workspace_path: Path, snapshot: RepositorySnapshot):
        self.workspace = workspace_path
        self.snapshot = snapshot

        self.functions: list[FunctionNode] = []
        self.classes: list[ClassNode] = []
        self.imports: list[ImportNode] = []
        self.calls: list[CallNode] = []

        self._build_indexes()

    def _build_indexes(self) -> None:
        for file_inv in self.snapshot.files:
            if file_inv.language == "python":
                full_path = self.workspace if self.workspace.is_file() else (self.workspace / file_inv.file_path)
                try:
                    code = full_path.read_text(encoding="utf-8")
                    visitor = CodeParser.parse_python_file(file_inv.file_path, code)
                    self.functions.extend(visitor.functions)
                    self.classes.extend(visitor.classes)
                    self.imports.extend(visitor.imports)
                    self.calls.extend(visitor.calls)
                except Exception:
                    continue

    def get_functions_by_name(self, name: str) -> list[FunctionNode]:
        return [f for f in self.functions if f.name == name]

    def get_calls_to(self, callee_name: str) -> list[CallNode]:
        return [c for c in self.calls if c.callee_name == callee_name]
