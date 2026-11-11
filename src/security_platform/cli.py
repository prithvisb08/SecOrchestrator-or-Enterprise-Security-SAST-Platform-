from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from security_platform.analysis.orchestrator import ScanOrchestrator
from security_platform.reporting.exporter import ReportExporter

app = typer.Typer(help="Enterprise Security Platform CLI", no_args_is_help=True)
console = Console()


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context) -> None:
    """Main callback to support both direct and sub-command invocations."""
    pass


@app.command("scan", help="Performs a comprehensive multi-engine security scan on a repository directory.")
def scan_repository(
    target_dir: Path = typer.Argument(..., help="Path to the repository to scan", exists=True),
    output_format: str = typer.Option("cli", "--format", "-f", help="Output format: cli, json, sarif"),
    asset_criticality: float = typer.Option(1.0, "--criticality", "-c", help="Asset criticality multiplier (0.5 to 2.0)"),
) -> None:
    """Performs a comprehensive multi-engine security scan on a repository directory."""
    if output_format == "cli":
        console.print(f"[bold blue]Starting security scan on target:[/bold blue] {target_dir}")

    orchestrator = ScanOrchestrator()
    result = orchestrator.run_scan(target_dir, asset_criticality=asset_criticality)

    # Output formatting
    exporter = ReportExporter()
    if output_format == "json":
        typer.echo(exporter.to_json(result.repository_id, result.findings, result.risk_assessment))
        return
    elif output_format == "sarif":
        typer.echo(exporter.to_sarif(result.repository_id, result.findings))
        return

    # Default CLI Rich Table Output
    console.print("\n[bold green]=== Scan Complete ===[/bold green]")
    console.print(
        f"Overall Risk Score: [bold red]{result.risk_assessment.overall_risk_score}/10.0[/bold red] "
        f"({result.risk_assessment.risk_level.value})"
    )
    console.print(f"Total Findings Detected: {result.findings_count}")
    if result.scan_errors:
        console.print(f"[bold yellow]Scan completed with {len(result.scan_errors)} file error(s)[/bold yellow]")

    if result.findings:
        table = Table(title="Security Findings Summary")
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Type", style="cyan", width=22)
        table.add_column("File:Line", style="magenta", width=25)
        table.add_column("Title", style="white")

        for f in result.findings:
            vuln_type = f.vulnerability_type.value if hasattr(f.vulnerability_type, "value") else str(f.vulnerability_type)
            table.add_row(
                str(f.severity.value),
                str(vuln_type),
                f"{f.location.file_path}:{f.location.start_line}",
                f.title,
            )
        console.print(table)
    else:
        console.print("[green]No vulnerabilities found. Great job![/green]")


if __name__ == "__main__":
    app()
