import json
from pathlib import Path

from pydantic import BaseModel


class Dependency(BaseModel):
    name: str
    version: str
    ecosystem: str
    manifest_path: str
    is_transitive: bool = False


class DependencyAnalyzer:
    def analyze_manifest(self, file_path: str, content: str) -> list[Dependency]:
        deps = []
        path = Path(file_path)
        filename = path.name

        if filename == "requirements.txt":
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split("==")
                    name = parts[0].strip()
                    version = parts[1].strip() if len(parts) > 1 else "latest"
                    deps.append(Dependency(name=name, version=version, ecosystem="pip", manifest_path=file_path))

        elif filename == "pyproject.toml":
            try:
                import tomllib
                data = tomllib.loads(content)
                project = data.get("project", {})
                for dep in project.get("dependencies", []):
                    name = dep.split(">=")[0].split("==")[0].strip()
                    deps.append(Dependency(name=name, version="unknown", ecosystem="pip", manifest_path=file_path))
            except Exception:
                pass

        elif filename == "package.json":
            try:
                data = json.loads(content)
                for section in ["dependencies", "devDependencies"]:
                    for name, version in data.get(section, {}).items():
                        clean_version = version.replace("^", "").replace("~", "")
                        deps.append(Dependency(name=name, version=clean_version, ecosystem="npm", manifest_path=file_path))
            except Exception:
                pass

        return deps
