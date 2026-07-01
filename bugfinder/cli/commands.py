from __future__ import annotations

import typer
from rich import print as rprint
from rich.panel import Panel

from bugfinder import __version__

app = typer.Typer(
    name="bf",
    help="BugFinder - AI-powered autonomous bug bounty assistant",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def _version_callback(value: bool) -> None:
    if value:
        rprint(f"[bold]BugFinder[/bold] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True
    ),
) -> None:
    pass


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target to scan (URL, APK, IP, domain, etc.)"),
    profile: str = typer.Option("auto", "--profile", "-p", help="Scan profile"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Quick scan"),
    deep: bool = typer.Option(False, "--deep", "-d", help="Deep scan"),
    expert: bool = typer.Option(False, "--expert", "-e", help="Expert mode"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output report path"),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format"),
) -> None:
    """Scan a target for security vulnerabilities."""
    from bugfinder.target.detector import detect_target_type, normalize_target
    from bugfinder.target.parsers import Target

    target_type = detect_target_type(target)
    normalized = normalize_target(target)
    t = Target(target, target_type, normalized=normalized)

    rprint(
        Panel.fit(
            f"[bold yellow]BugFinder[/bold yellow] v{__version__}\n"
            f"Target: [cyan]{t.raw}[/cyan]\n"
            f"Type: [green]{t.type.value}[/green]\n"
            f"{'Profile: ' + profile if profile != 'auto' else ''}",
            border_style="yellow",
        )
    )

    if expert:
        _run_expert_scan(t, profile)
    else:
        _run_guided_scan(t, quick=quick, deep=deep)


@app.command()
def tui() -> None:
    """Launch the Textual terminal UI dashboard."""
    from bugfinder.cli.app import BugFinderTUI

    app = BugFinderTUI()
    app.run()


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan session ID"),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output path"),
) -> None:
    """Generate a report from a completed scan."""
    rprint(f"[yellow]Generating {format} report for scan {scan_id}...[/yellow]")


@app.command()
def config(
    key: str = typer.Argument(..., help="Config key"),
    value: str = typer.Argument(..., help="Config value"),
) -> None:
    """Set a configuration value."""
    rprint(f"[green]Set {key} = {value}[/green]")


@app.command()
def list_agents() -> None:
    """List available assessment agents."""
    from bugfinder.core.registry import registry

    registry.discover_agents()
    agents = registry.list_agents()
    if agents:
        rprint("[bold]Available agents:[/bold]")
        for name in agents:
            rprint(f"  • {name}")
    else:
        rprint("[yellow]No agents found.[/yellow]")


@app.command()
def plugin(
    action: str = typer.Argument(..., help="Action: install, remove, list"),
    name: str | None = typer.Argument(None, help="Plugin name"),
) -> None:
    """Manage plugins."""
    rprint(f"[yellow]Plugin {action}: {name or 'all'}[/yellow]")


def _run_guided_scan(target, quick: bool = False, deep: bool = False) -> None:
    rprint("[green]Starting guided scan...[/green]")
    if quick:
        rprint("[blue]Quick mode: basic checks only[/blue]")
    if deep:
        rprint("[blue]Deep mode: thorough assessment[/blue]")
    rprint("[bold]Coming soon: Full scan engine in Phase 2[/bold]")


def _run_expert_scan(target, profile: str) -> None:
    rprint("[green]Starting expert scan...[/green]")
    rprint(f"[blue]Profile: {profile}[/blue]")
    rprint("[bold]Coming soon: Expert mode in Phase 2[/bold]")
