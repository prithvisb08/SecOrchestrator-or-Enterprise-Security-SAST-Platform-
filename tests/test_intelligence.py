
import pytest

from security_platform.ingestion.models import FileInventory, RepositorySnapshot
from security_platform.intelligence.context import AnalyzerContext
from security_platform.intelligence.parser import CodeParser


@pytest.fixture
def sample_python_code():
    return """
import os
from subprocess import Popen

@require_auth
def execute_system(cmd, user_id):
    local_var = "test"
    Popen(cmd)
    return True

class HelperTask:
    def async_process(self):
        execute_system("ls", 1)
"""

def test_python_ast_extraction(sample_python_code):
    visitor = CodeParser.parse_python_file("src/main.py", sample_python_code)

    # Check Imports
    assert len(visitor.imports) == 2
    assert visitor.imports[1].name == "Popen"

    # Check Functions
    assert len(visitor.functions) == 2
    func = visitor.functions[0]
    assert func.name == "execute_system"
    assert "require_auth" in func.decorators
    assert "local_var" in func.local_variables
    assert func.has_return is True

    # Check Call Graph
    calls = [c.callee_name for c in visitor.calls]
    assert "Popen" in calls
    assert "execute_system" in calls

def test_graceful_syntax_error():
    bad_code = "def oops(] this is not valid python"
    visitor = CodeParser.parse_python_file("src/bad.py", bad_code)
    assert len(visitor.functions) == 0  # Should not raise an exception

def test_analyzer_context(tmp_path, sample_python_code):
    code_file = tmp_path / "main.py"
    code_file.write_text(sample_python_code)

    snapshot = RepositorySnapshot(
        repository_id="test",
        scanner_version="1.0",
        files=[FileInventory(file_path="main.py", size_bytes=100, sha256_hash="hash", language="python")]
    )

    ctx = AnalyzerContext(tmp_path, snapshot)

    assert len(ctx.get_calls_to("Popen")) == 1
    assert len(ctx.get_functions_by_name("execute_system")) == 1
