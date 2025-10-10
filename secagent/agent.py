from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from secagent.tools.pip_audit import run_pip_audit

app = typer.Typer(add_completion=False)
console = Console()

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    Security AI Agent: orchestrates scanners and summarizes findings
    """
    if ctx.invoked_subcommand is None:
        typer.echo("Use 'sec-agent --help' to see available commands.")
        raise typer.Exit()

@app.command()
def scan(
    target: Path = typer.Option(
        Path("."), "--target", "-t", exists=True, file_okay=False, dir_okay=True,
        help="Project directory to scan (used to detect requirements.txt)."
    ),
    requirements: Optional[Path] = typer.Option(
        None, "--requirements", "-r", exists=True, file_okay=True, dir_okay=False,
        help="Explicit requirements.txt to audit. If omitted, tries target/requirements.txt; otherwise audits current environment."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Write JSON to file. If omitted, prints to stdout."
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress pretty console banners."
    ),
):
    """
    Run pip-audit and emit JSON (MVP).
    """
    if not quiet:
        console.print(Panel.fit("[bold]Security AI Agent[/bold] — pip-audit MVP", subtitle="scan"))

    results, meta = run_pip_audit(target=target, requirements=requirements)

    payload = {
        "tool": "pip-audit",
        "target": str(target.resolve()),
        "meta": meta,
        "results": results,
    }

    data = json.dumps(payload, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(data, encoding="utf-8")
        if not quiet:
            console.print(f"[green]Wrote JSON to {output}[/green]")
    else:
        typer.echo(data)

if __name__ == "__main__":
    app()