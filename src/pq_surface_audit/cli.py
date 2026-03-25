from __future__ import annotations

from pathlib import Path
import typer

from pq_surface_audit.report import write_report
from pq_surface_audit.scanner import load_targets_file, scan_batch

app = typer.Typer(add_completion=False, help="External PQ readiness scanner for authorized assets.")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL, host, or host:port"),
    output: str = typer.Option("./out", help="Directory to write report.json and report.html"),
    timeout: float = typer.Option(5.0, help="Network timeout in seconds"),
    no_ssh: bool = typer.Option(False, help="Skip SSH checks"),
) -> None:
    """Scan a single target."""
    report = scan_batch([target], timeout=timeout, include_ssh=not no_ssh)
    json_path, html_path = write_report(report, output)
    typer.echo(f"JSON report: {json_path}")
    typer.echo(f"HTML report: {html_path}")


@app.command()
def batch(
    targets_file: str = typer.Argument(..., help="File containing one target per line"),
    output: str = typer.Option("./out", help="Directory to write report.json and report.html"),
    timeout: float = typer.Option(5.0, help="Network timeout in seconds"),
    no_ssh: bool = typer.Option(False, help="Skip SSH checks"),
) -> None:
    """Scan multiple targets from a file."""
    targets = load_targets_file(targets_file)
    report = scan_batch(targets, timeout=timeout, include_ssh=not no_ssh)
    json_path, html_path = write_report(report, output)
    typer.echo(f"JSON report: {json_path}")
    typer.echo(f"HTML report: {html_path}")


if __name__ == "__main__":
    app()
