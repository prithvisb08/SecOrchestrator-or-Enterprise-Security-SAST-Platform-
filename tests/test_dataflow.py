import pytest

from security_platform.dataflow.engine import DataFlowEngine
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


@pytest.fixture
def dataflow_engine():
    return DataFlowEngine()

def test_direct_taint_flow(dataflow_engine):
    """Tests a direct flow from request to sqlite3 (Positive Case)."""
    code = """
import sqlite3
def get_user(request):
    # Source
    user_id = request.GET.get('id')
    # Sink
    sqlite3.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    findings = dataflow_engine.analyze_file("src/views.py", code)
    assert len(findings) == 1
    assert findings[0].vulnerability_type == VulnerabilityType.SQL_INJECTION
    assert "request.GET.get" in findings[0].evidence
    assert "sqlite3.execute" in findings[0].evidence

def test_propagated_taint_flow(dataflow_engine):
    """Tests taint propagating through multiple variable assignments (Positive Case)."""
    code = """
import os
def run_command():
    user_input = os.environ.get('CMD')
    step_1 = user_input
    step_2 = f"echo {step_1}"
    os.system(step_2)
"""
    findings = dataflow_engine.analyze_file("src/cli.py", code)
    assert len(findings) == 1
    assert findings[0].vulnerability_type == VulnerabilityType.COMMAND_INJECTION

def test_sanitized_flow(dataflow_engine):
    """Tests that a sanitizer correctly breaks the taint chain (Negative Case)."""
    code = """
import shlex
import os
def run_safe_command():
    user_input = os.environ.get('CMD')

    # Sanitization breaks the taint
    safe_input = shlex.quote(user_input)

    os.system(safe_input)
"""
    findings = dataflow_engine.analyze_file("src/safe_cli.py", code)
    assert len(findings) == 0

def test_type_cast_sanitization(dataflow_engine):
    """Tests that casting an input to an integer sanitizes it for SQL (Negative Case)."""
    code = """
import sqlite3
def get_user_safe(request):
    user_id_raw = request.GET.get('id')

    # Casting to integer is a safe transformation
    user_id = int(user_id_raw)

    sqlite3.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    findings = dataflow_engine.analyze_file("src/safe_views.py", code)
    assert len(findings) == 0

def test_safe_data_no_taint(dataflow_engine):
    """Ensures safe hardcoded strings do not trigger findings (Negative Case)."""
    code = """
import sqlite3
def run_internal_query():
    table_name = "admin_users"
    sqlite3.execute(f"SELECT * FROM {table_name}")
"""
    findings = dataflow_engine.analyze_file("src/internal.py", code)
    assert len(findings) == 0
