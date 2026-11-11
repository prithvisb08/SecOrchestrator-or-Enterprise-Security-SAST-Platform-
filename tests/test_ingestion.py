import tempfile
import zipfile
from pathlib import Path

import pytest

from security_platform.ingestion.discovery import ProjectDiscovery
from security_platform.ingestion.engines import IgnoreRuleEngine
from security_platform.ingestion.loaders import ArchiveLoader, LocalLoader


def test_ignore_rule_engine_filters_git():
    engine = IgnoreRuleEngine()
    assert engine.should_ignore(Path(".git/config")) is True
    assert engine.should_ignore(Path("src/main.py")) is False

def test_archive_loader_path_traversal():
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        with zipfile.ZipFile(tmp, 'w') as zf:
            zf.writestr("../malicious.sh", "echo 'hacked'")
        with pytest.raises(ValueError, match="Path traversal detected"):
            ArchiveLoader(tmp.name)

def test_project_discovery_builds_snapshot(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hello')")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0")

    loader = LocalLoader(str(tmp_path))
    discovery = ProjectDiscovery(loader)
    snapshot = discovery.build_snapshot("repo-123")

    assert snapshot.total_files == 2
    assert "requests==2.31.0" in [Path(tmp_path / f.file_path).read_text() for f in snapshot.files]
    assert "requirements.txt" in snapshot.manifests_detected
    assert snapshot.language_statistics.get("python") == 1
