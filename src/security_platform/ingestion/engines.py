from pathlib import Path


class IgnoreRuleEngine:
    DEFAULT_IGNORES = {".git", "node_modules", "venv", "build", "__pycache__", "dist"}
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, custom_ignores: set[str] | None = None):
        self.ignores = self.DEFAULT_IGNORES.union(custom_ignores or set())

    def should_ignore(self, path: Path) -> bool:
        if any(part in self.ignores for part in path.parts):
            return True
        if path.exists():
            if path.is_dir():
                return False
            if not path.is_file() or path.is_symlink():
                return True
            if path.stat().st_size > self.MAX_FILE_SIZE:
                return True
            return self._is_binary(path)
        return False

    def _is_binary(self, path: Path) -> bool:
        try:
            with open(path, 'rb') as f:
                chunk = f.read(1024)
                return b'\0' in chunk
        except Exception:
            return True


class LanguageDetector:
    EXT_MAP = {".py": "python", ".js": "javascript", ".java": "java", ".go": "go", ".rs": "rust"}
    MANIFESTS = {"requirements.txt", "pyproject.toml", "package.json", "pom.xml", "go.mod", "Dockerfile"}

    @classmethod
    def detect_language(cls, path: Path) -> str | None:
        return cls.EXT_MAP.get(path.suffix.lower())

    @classmethod
    def is_manifest(cls, path: Path) -> bool:
        return path.name in cls.MANIFESTS
