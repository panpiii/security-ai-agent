from __future__ import annotations

from secagent.tools.bandit_scan import run_bandit


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
    with_llm: bool = typer.Option(False, "--with-llm", help="Generate an LLM summary."),
    llm_provider: str = typer.Option("openai", "--llm-provider", help="LLM provider: openai (default)."),
    llm_model: str = typer.Option("gpt-4o-mini", "--llm-model", help="LLM model name."),
    summary_format: str = typer.Option("md", "--summary-format", help="Summary format: md|json."),
    summary_output: Optional[Path] = typer.Option(None, "--summary-output", help="Write LLM summary to a file."),
):
    """
    Run pip-audit (deps) + Bandit (code) and emit a combined JSON report.
    """
    if not quiet:
        console.print(Panel.fit("[bold]Security AI Agent[/bold] — combined scan", subtitle="pip-audit + bandit"))

    # --- pip-audit ---
    pa_results_raw, pa_meta = run_pip_audit(target=target, requirements=requirements)
    # normalize shape across pip-audit versions:
    # some return list, some return {"dependencies":[...], "fixes":[...]}
    if isinstance(pa_results_raw, dict):
        pa_deps = pa_results_raw.get("dependencies", [])
        pa_fixes = pa_results_raw.get("fixes", [])
    else:
        pa_deps = pa_results_raw
        pa_fixes = []

    # quick counts for convenience
    pa_vuln_count = sum(len(d.get("vulns", [])) for d in pa_deps)

    # --- Bandit ---
    bandit_results, bandit_meta = run_bandit(target=target)
    # bandit JSON has "results": [..] and "metrics": {...}
    b_findings = bandit_results.get("results", []) if isinstance(bandit_results, dict) else []
    b_issue_count = len(b_findings)

    # --- Combined payload ---
    payload = {
        "tool": "security-ai-agent",
        "target": str(target.resolve()),
        "meta": {
            "generated_by": "sec-agent",
            "scanners": {
                "pip_audit": {**pa_meta, "finding_count": pa_vuln_count},
                "bandit":    {**bandit_meta, "finding_count": b_issue_count},
            }
        },
        "results": {
            "pip_audit": {
                "dependencies": pa_deps,
                "fixes": pa_fixes,
            },
            "bandit": bandit_results,
        },
        "summary": {
            "dependency_vulnerabilities": pa_vuln_count,
            "code_issues": b_issue_count,
        }
    }

    data = json.dumps(payload, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(data, encoding="utf-8")
        if not quiet:
            console.print(f"[green]Wrote JSON to {output}[/green]")
    else:
        typer.echo(data)
    # -- LLM summary (optional)
    if with_llm:
        try:
            if llm_provider.lower() == "openai":
                from secagent.summarizers.openai_summarizer import OpenAISummarizer
                summarizer = OpenAISummarizer(model=llm_model)
            else:
                raise RuntimeError(f"Unsupported provider: {llm_provider}")

            llm_text = summarizer.summarize(payload, out_format=summary_format)  # "md" or "json"

            if summary_output:
                summary_output.parent.mkdir(parents=True, exist_ok=True)
                summary_output.write_text(llm_text, encoding="utf-8")
                if not quiet:
                    console.print(f"[green]Wrote LLM summary to {summary_output}[/green]")
            else:
                if not quiet:
                    console.rule("[bold]LLM Summary[/bold]")
                typer.echo(llm_text)
        except Exception as e:
            console.print(f"[yellow]LLM summary skipped: {e}[/yellow]")
  

    # exit code policy (MVP): non-zero if any findings
    if pa_vuln_count > 0 or b_issue_count > 0:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()