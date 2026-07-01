from __future__ import annotations

import asyncio
import time
from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from bugfinder import __version__
from bugfinder.core.config import settings

app = typer.Typer(
    name="bf",
    help="BugFinder - AI-powered autonomous bug bounty assistant",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


def _version_callback(value: bool) -> None:
    if value:
        rprint(f"[bold]BugFinder[/bold] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", "-V", callback=_version_callback, is_eager=True),
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
    report_format: str = typer.Option("markdown", "--format", "-f", help="Report format"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI features"),
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

    if no_ai:
        settings.ai_enabled = False

    if quick:
        profile = "quick"
    if deep:
        profile = "deep"

    _run_scan(t, profile=profile, expert=expert, output=output, report_format=report_format)


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
    if key == "nvidia.api_key":
        settings.nvidia_api_key = value
        rprint("[green]✓ NVIDIA API key configured[/green]")
    elif key == "beginner_mode":
        settings.beginner_mode = value.lower() in ("true", "1", "yes")
        rprint(f"[green]✓ Beginner mode set to {settings.beginner_mode}[/green]")
    else:
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
        from bugfinder.planner.rule_planner import TARGET_PLANS

        all_agents = set()
        for plans in TARGET_PLANS.values():
            for p in plans:
                all_agents.add(p["agent"])
        rprint("[bold]Available agents (from rule planner):[/bold]")
        for a in sorted(all_agents):
            rprint(f"  • {a}")


@app.command()
def plugin(
    action: str = typer.Argument(..., help="Action: install, remove, list"),
    name: str | None = typer.Argument(None, help="Plugin name"),
) -> None:
    """Manage plugins."""
    rprint(f"[yellow]Plugin {action}: {name or 'all'}[/yellow]")


def _run_scan(
    target,
    profile: str = "auto",
    expert: bool = False,
    output: str | None = None,
    report_format: str = "markdown",
) -> None:
    asyncio.run(_async_scan(target, profile, expert, output, report_format))


async def _async_scan(
    target,
    profile: str = "auto",
    expert: bool = False,
    output: str | None = None,
    report_format: str = "markdown",
) -> None:
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session_factory
    from bugfinder.engine.scheduler import ScanOrchestrator
    from bugfinder.knowledge_graph.graph import KnowledgeGraph
    from bugfinder.reporting.markdown import generate_markdown_report

    kg = KnowledgeGraph()
    ai_client = None
    if settings.ai_enabled and settings.nvidia_api_key:
        from bugfinder.ai.client import NVIDIAClient

        ai_client = NVIDIAClient()
        available = await ai_client.is_available()
        if not available:
            rprint("[yellow]⚠ NVIDIA API not available. Running without AI. Set BF_NVIDIA_API_KEY.[/yellow]")
            ai_client = None
            settings.ai_enabled = False

    repo = None
    scan_id = "local-scan"
    try:
        async with async_session_factory() as session:
            repo = Repository(session)
            scan_record = await repo.create_scan(
                target=target.raw,
                target_type=target.type.value,
            )
            scan_id = scan_record.id
    except Exception:
        pass

    ScanOrchestrator(kg, ai_client, repo)

    ttype = target.type.value

    rprint(f"\n[bold]Scan Plan[/bold] ({target.type.value})")
    rprint("─" * 50)

    start_time = time.monotonic()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Step 0/? — Initializing...", total=100)
        progress.update(task, completed=0)

        if profile == "quick":
            from bugfinder.planner.rule_planner import PLANNER_STRATEGIES

            steps = PLANNER_STRATEGIES.get("quick", [])
            rprint("  [blue]Quick mode: basic checks only[/blue]")
        else:
            from bugfinder.core.types import TargetType
            from bugfinder.planner.rule_planner import TARGET_PLANS

            try:
                tt = TargetType(ttype)
            except ValueError:
                tt = None
            steps_def = TARGET_PLANS.get(tt, [])
            steps = (
                steps_def
                if not expert
                else steps_def
                + [
                    {"agent": "secrets.scan", "rationale": "Deep secrets scan"},
                ]
            )

        rprint("")
        for i, s in enumerate(steps):
            rprint(f"  {i + 1}. {s['rationale']}")

        rprint("")
        rprint("[bold]Starting scan...[/bold]")
        rprint("")

        total = len(steps)
        for i, step_def in enumerate(steps):
            agent_name = step_def["agent"]
            rationale = step_def["rationale"]
            desc = f"[cyan]Step {i + 1}/{total} — {rationale}"
            progress.update(task, description=desc, completed=int((i / total) * 100))

            from bugfinder.agents.base import AgentContext

            ctx = AgentContext(
                target=target.normalized,
                target_type=ttype,
                scan_id=scan_id,
                knowledge_graph=kg,
                ai_client=ai_client,
                repository=repo,
            )

            agent = await _load_agent(agent_name, ctx)
            try:
                result = await agent.execute()
                if result.findings:
                    for f in result.findings:
                        f_id = f.get("id", f"f-{id(f)}")
                        kg.add_node(f_id, "finding", **f)
                        rprint(f"    [yellow]⚠ {f['title']}[/yellow] ({f['severity']})")
                if result.assets:
                    for a in result.assets:
                        a_id = a.get("id", f"a-{id(a)}")
                        kg.add_node(a_id, "asset", **a)
                rprint(f"    [green]✓ {result.summary}[/green]")
            except Exception as e:
                rprint(f"    [red]✗ {agent_name} failed: {e}[/red]")

        progress.update(task, description="[green]Scan complete!", completed=100)

    elapsed = time.monotonic() - start_time

    all_findings = [dict(d) for n, d in kg.graph.nodes(data=True) if d.get("type") == "finding"]
    all_assets = [dict(d) for n, d in kg.graph.nodes(data=True) if d.get("type") == "asset"]

    rprint("")
    rprint(
        Panel.fit(
            f"[bold]Scan Complete[/bold]\n"
            f"Findings: {len(all_findings)}\n"
            f"Assets: {len(all_assets)}\n"
            f"Duration: {_format_duration(elapsed)}",
            border_style="green",
        )
    )

    if all_findings:
        table = Table(title="Findings Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Confidence")
        for f in sorted(
            all_findings,
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                x.get("severity", "info"), 99
            ),
        ):
            sev = f.get("severity", "info")
            style = {
                "critical": "red",
                "high": "orange1",
                "medium": "yellow",
                "low": "blue",
                "info": "dim white",
            }.get(sev, "")
            table.add_row(
                f"[{style}]{sev.upper()}[/{style}]",
                f.get("title", "Untitled")[:60],
                f.get("confidence", "needs_review"),
            )
        console.print(table)

    report_md = generate_markdown_report(
        target=target.raw,
        target_type=ttype,
        findings=all_findings,
        assets=all_assets,
        scan_duration=elapsed,
    )

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report_md, encoding="utf-8")
        rprint(f"\n[green]Report saved to {out_path}[/green]")
    else:
        reports_dir = settings.reports_path
        reports_dir.mkdir(parents=True, exist_ok=True)
        safe_name = target.raw.replace("://", "_").replace("/", "_").replace(".", "_")
        out_path = reports_dir / f"report_{safe_name}_{scan_id[:8]}.md"
        out_path.write_text(report_md, encoding="utf-8")
        rprint(f"\n[green]Report saved to {out_path}[/green]")

    if repo and scan_id != "local-scan":
        try:
            async with async_session_factory() as session:
                repo = Repository(session)
                await repo.update_scan(
                    scan_id,
                    status="completed",
                    completed_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
                    progress=100.0,
                )
        except Exception:
            pass


async def _load_agent(agent_name: str, ctx) -> any:
    from bugfinder.agents.api.discover import APIDiscoverAgent
    from bugfinder.agents.base import AgentResult, BaseAgent
    from bugfinder.agents.recon.dns import DNSAgent
    from bugfinder.agents.recon.tech import TechDetectAgent
    from bugfinder.agents.secrets.scan import SecretsScanAgent
    from bugfinder.agents.verification.verify import VerificationAgent
    from bugfinder.agents.web.crawler import CrawlerAgent
    from bugfinder.agents.web.sqli import SQLiAgent
    from bugfinder.agents.web.xss import XSSAgent

    agent_map = {
        "recon.dns": DNSAgent,
        "recon.tech": TechDetectAgent,
        "recon.whois": None,
        "recon.cert": None,
        "web.crawler": CrawlerAgent,
        "web.js": None,
        "web.auth": None,
        "web.xss": XSSAgent,
        "web.sqli": SQLiAgent,
        "web.ssrf": None,
        "web.lfi": None,
        "api.discover": APIDiscoverAgent,
        "api.auth": None,
        "api.fuzz": None,
        "api.rate": None,
        "secrets.scan": SecretsScanAgent,
        "verification": VerificationAgent,
        "infra.port": None,
        "infra.service": None,
        "android.decompile": None,
        "android.manifest": None,
        "android.web": None,
    }

    cls = agent_map.get(agent_name)
    if cls:
        return cls(ctx)

    class StubAgent(BaseAgent):
        name = agent_name
        description = f"Stub for {agent_name}"

        async def execute(self) -> AgentResult:
            return AgentResult(
                agent_name=agent_name,
                status="completed",
                summary="⏭ Not yet implemented",
            )

    return StubAgent(ctx)


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    h, m = divmod(int(seconds), 3600)
    return f"{h}h {m}m"
