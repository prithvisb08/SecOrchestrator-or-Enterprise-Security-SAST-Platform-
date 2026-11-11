import json

from typer.testing import CliRunner

from security_platform.cli import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Enterprise Security Platform CLI" in result.output


def test_cli_scan_default_table(tmp_path):
    vuln_file = tmp_path / "main.py"
    vuln_file.write_text("import hashlib\nh = hashlib.md5(b'test')\n")

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "=== Scan Complete ===" in result.output
    assert "Overall Risk Score" in result.output


def test_cli_scan_json_output(tmp_path):
    vuln_file = tmp_path / "main.py"
    vuln_file.write_text("import hashlib\nh = hashlib.md5(b'test')\n")

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "repository_id" in data
    assert "findings" in data
    assert "risk_assessment" in data


def test_cli_scan_sarif_output(tmp_path):
    vuln_file = tmp_path / "main.py"
    vuln_file.write_text("import hashlib\nh = hashlib.md5(b'test')\n")

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert "runs" in data
