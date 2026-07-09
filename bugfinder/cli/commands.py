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
def web(
    host: str = typer.Option("127.0.0.1", "--host", "-H", help="Host to bind to"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind to"),
) -> None:
    """Launch the BugFinder Web UI."""
    import uvicorn
    rprint(f"[green]Starting BugFinder Web UI on http://{host}:{port}[/green]")
    uvicorn.run("bugfinder.web.app:app", host=host, port=port, log_level="info")


@app.command()
def report(
    scan_id: int = typer.Argument(..., help="Scan session ID"),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output path"),
) -> None:
    """Generate a report from a completed scan."""
    rprint(f"[yellow]Generating {format} report for scan {scan_id}...[/yellow]")

    _generate_report(scan_id, format, output)


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
    from bugfinder.planner.rule_planner import TARGET_PLANS

    all_agents: set[str] = set()
    for plans in TARGET_PLANS.values():
        for p in plans:
            all_agents.add(p["agent"])

    table = Table(title="Available Agents")
    table.add_column("Agent Name", style="cyan")
    table.add_column("Category")
    for agent in sorted(all_agents):
        category = agent.split(".")[0] if "." in agent else "other"
        table.add_row(agent, category)
    console.print(table)
    rprint(f"\n[bold]{len(all_agents)} agents total[/bold]")


@app.command()
def plugin(
    action: str = typer.Argument(..., help="Action: install, remove, list"),
    name: str | None = typer.Argument(None, help="Plugin name"),
) -> None:
    """Manage plugins."""
    rprint(f"[yellow]Plugin {action}: {name or 'all'}[/yellow]")


def _run_scan(target, profile: str = "auto", expert: bool = False,
              output: str | None = None, report_format: str = "markdown") -> None:
    asyncio.run(_async_scan(target, profile, expert, output, report_format))


async def _async_scan(target, profile: str = "auto", expert: bool = False,
                      output: str | None = None, report_format: str = "markdown") -> None:
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session
    from bugfinder.engine.scheduler import ScanOrchestrator
    from bugfinder.knowledge_graph.graph import KnowledgeGraph
    from bugfinder.reporting.html import generate_html_report
    from bugfinder.reporting.json_report import generate_json_report
    from bugfinder.reporting.markdown import generate_markdown_report
    from bugfinder.core.types import TargetType

    report_generators = {
        "markdown": generate_markdown_report,
        "html": generate_html_report,
        "json": generate_json_report,
    }

    kg = KnowledgeGraph()
    ai_client = None
    if settings.ai_enabled:
        from bugfinder.ai.client import get_ai_client
        ai_client = get_ai_client()
        if ai_client:
            available = await ai_client.is_available()
            if not available:
                rprint("[yellow]⚠ AI provider not available.[/yellow]")
                ai_client = None
                settings.ai_enabled = False

    scan_id = 0
    try:
        async with async_session() as session:
            repo = Repository(session)
            ttype = TargetType.UNKNOWN
            try:
                ttype = TargetType(target.type.value)
            except ValueError:
                pass
            scan_record = await repo.create_scan(
                target=target.raw,
                target_type=ttype,
                profile=profile,
            )
            scan_id = scan_record.id
    except Exception as e:
        rprint(f"[yellow]DB error (scans still work): {e}[/yellow]")

    orchestrator = ScanOrchestrator(kg, ai_client, None)
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
            steps_def = [
                {"agent": "recon.dns", "rationale": "Quick DNS check"},
                {"agent": "recon.tech", "rationale": "Technology identification"},
                {"agent": "web.crawler", "rationale": "Fast crawl"},
                {"agent": "web.xss", "rationale": "Basic XSS check"},
                {"agent": "web.sqli", "rationale": "Basic SQLi check"},
                {"agent": "secrets.scan", "rationale": "Secret scanning"},
            ]
        else:
            from bugfinder.planner.rule_planner import TARGET_PLANS

            try:
                tt = TargetType(ttype)
            except ValueError:
                tt = TargetType.UNKNOWN
            steps_def = TARGET_PLANS.get(tt, [])
            if expert:
                steps_def = steps_def + [
                    {"agent": "web.race", "rationale": "Race condition testing"},
                    {"agent": "web.xxe", "rationale": "XXE injection testing"},
                ]

        rprint("")
        for i, s in enumerate(steps_def):
            rprint(f"  {i + 1}. {s['rationale']}")

        rprint("")
        rprint("[bold]Starting scan...[/bold]")
        rprint("")

        total = len(steps_def)
        for i, step_def in enumerate(steps_def):
            agent_name = step_def["agent"]
            rationale = step_def["rationale"]
            desc = f"[cyan]Step {i + 1}/{total} — {rationale}"
            progress.update(task, description=desc, completed=int((i / total) * 100))

            agent = await _load_agent(agent_name)
            from bugfinder.target.parsers import parse_target
            from bugfinder.agents.base import AgentContext

            ctx = AgentContext(
                target=parse_target(target.raw),
                target_type=ttype,
                knowledge_graph=kg,
                ai_client=ai_client,
                repository=None,
            )

            try:
                result = await agent.execute(ctx)
                if result and result.findings:
                    for f in result.findings:
                        f_id = f.get("id", f"f-{id(f)}")
                        kg.add_node(f_id, "finding", **f)
                        rprint(f"    [yellow]⚠ {f['title']}[/yellow] ({f.get('severity', 'info')})")
                if result and result.summary:
                    rprint(f"    [green]✓ {result.summary}[/green]")
                else:
                    rprint(f"    [green]✓ {agent_name} completed[/green]")
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
                f.get("confidence", "medium"),
            )
        console.print(table)

    generator = report_generators.get(report_format, report_generators["markdown"])
    report_content = generator(
        target=target.raw,
        scan_id=scan_id,
        findings=all_findings,
        assets=all_assets,
        scan_duration=elapsed,
    )

    ext = {"markdown": ".md", "html": ".html", "json": ".json"}.get(report_format, ".md")

    if output:
        out_path = Path(output)
        if out_path.suffix == "":
            out_path = out_path.with_suffix(ext)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(report_content, str):
            out_path.write_text(report_content, encoding="utf-8")
        else:
            out_path.write_bytes(report_content)
        rprint(f"\n[green]Report saved to {out_path}[/green]")
    else:
        reports_dir = settings.reports_path
        reports_dir.mkdir(parents=True, exist_ok=True)
        safe_name = target.raw.replace("://", "_").replace("/", "_").replace(".", "_")
        out_path = reports_dir / f"report_{safe_name}_{scan_id}{ext}"
        if isinstance(report_content, str):
            out_path.write_text(report_content, encoding="utf-8")
        else:
            out_path.write_bytes(report_content)
        rprint(f"\n[green]Report saved to {out_path}[/green]")


def _generate_report(scan_id: int, fmt: str, output: str | None) -> None:
    asyncio.run(_async_report(scan_id, fmt, output))


async def _async_report(scan_id: int, fmt: str, output: str | None) -> None:
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session
    from bugfinder.reporting.markdown import generate_markdown_report
    from bugfinder.reporting.html import generate_html_report
    from bugfinder.reporting.json_report import generate_json_report

    generators = {
        "markdown": generate_markdown_report,
        "html": generate_html_report,
        "json": generate_json_report,
    }

    async with async_session() as session:
        repo = Repository(session)
        scan = await repo.get_scan(scan_id)
        if not scan:
            rprint(f"[red]Scan {scan_id} not found[/red]")
            return
        findings = await repo.list_findings(scan_id=scan_id)
        assets = await repo.list_assets(scan_id=scan_id)

    generator = generators.get(fmt, generators["markdown"])
    report = generator(
        target=scan.target,
        scan_id=scan_id,
        findings=findings,
        assets=assets,
    )

    ext = {"markdown": ".md", "html": ".html", "json": ".json"}.get(fmt, ".md")

    if output:
        out_path = Path(output)
        if out_path.suffix == "":
            out_path = out_path.with_suffix(ext)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report if isinstance(report, str) else str(report), encoding="utf-8")
        rprint(f"[green]Report saved to {out_path}[/green]")
    else:
        rprint(report[:2000] + "..." if len(str(report)) > 2000 else report)


async def _load_agent(agent_name: str):
    from bugfinder.agents.android.decompile import DecompileAgent
    from bugfinder.agents.android.deeplinks import DeepLinkAgent
    from bugfinder.agents.android.storage import AndroidStorageAgent
    from bugfinder.agents.android.webview import AndroidWebViewAgent
    from bugfinder.agents.api.discover import APIDiscoverAgent
    from bugfinder.agents.api.fuzz import APIFuzzAgent
    from bugfinder.agents.api.rate import APIRateAgent
    from bugfinder.agents.cloud.azure import AzureAgent
    from bugfinder.agents.cloud.detect import CloudAgent
    from bugfinder.agents.cloud.firebase import FirebaseAgent
    from bugfinder.agents.cloud.gcp import GCPAgent
    from bugfinder.agents.cloud.s3 import S3Agent
    from bugfinder.agents.correlation import CorrelationAgent
    from bugfinder.agents.infra.port import PortScanAgent
    from bugfinder.agents.infra.service import ServiceDetectAgent
    from bugfinder.agents.infra.tls import TLSScanAgent
    from bugfinder.agents.recon.dns import DNSAgent
    from bugfinder.agents.recon.github import GitHubAgent
    from bugfinder.agents.recon.googledorks import GoogleDorkAgent
    from bugfinder.agents.recon.tech import TechDetectAgent
    from bugfinder.agents.recon.wayback import WaybackAgent
    from bugfinder.agents.secrets.scan import SecretsScanAgent
    from bugfinder.agents.verification.verify import VerificationAgent
    from bugfinder.agents.web.auth import AuthAgent
    from bugfinder.agents.web.cache import CachePoisonAgent
    from bugfinder.agents.web.cookies import CookieSecurityAgent
    from bugfinder.agents.web.cors import CORSAgent
    from bugfinder.agents.web.crawler import CrawlerAgent
    from bugfinder.agents.web.csp import CSPAgent
    from bugfinder.agents.web.csrf import CSRFAgent
    from bugfinder.agents.web.graphql import GraphQLAgent
    from bugfinder.agents.web.host_header import HostHeaderAgent
    from bugfinder.agents.web.js import JSAnalyzerAgent
    from bugfinder.agents.web.jwt import JWTAgent
    from bugfinder.agents.web.lfi import LFIAgent
    from bugfinder.agents.web.race import RaceConditionAgent
    from bugfinder.agents.web.redirect import OpenRedirectAgent
    from bugfinder.agents.web.sqli import SQLiAgent
    from bugfinder.agents.web.ssrf import SSRFAgent
    from bugfinder.agents.web.ssti import SSTIAgent
    from bugfinder.agents.web.xss import XSSAgent
    from bugfinder.agents.web.xxe import XXEAgent
    from bugfinder.agents.base import AgentResult, BaseAgent

    agent_map: dict[str, type] = {
        "recon.dns": DNSAgent,
        "recon.tech": TechDetectAgent,
        "recon.wayback": WaybackAgent,
        "recon.github": GitHubAgent,
        "recon.googledorks": GoogleDorkAgent,
        "web.crawler": CrawlerAgent,
        "web.js": JSAnalyzerAgent,
        "web.auth": AuthAgent,
        "web.xss": XSSAgent,
        "web.sqli": SQLiAgent,
        "web.ssrf": SSRFAgent,
        "web.lfi": LFIAgent,
        "web.ssti": SSTIAgent,
        "web.xxe": XXEAgent,
        "web.graphql": GraphQLAgent,
        "web.jwt": JWTAgent,
        "web.cors": CORSAgent,
        "web.cookies": CookieSecurityAgent,
        "web.csrf": CSRFAgent,
        "web.csp": CSPAgent,
        "web.redirect": OpenRedirectAgent,
        "web.host_header": HostHeaderAgent,
        "web.race": RaceConditionAgent,
        "web.cache": CachePoisonAgent,
        "api.discover": APIDiscoverAgent,
        "api.fuzz": APIFuzzAgent,
        "api.rate": APIRateAgent,
        "secrets.scan": SecretsScanAgent,
        "correlation": CorrelationAgent,
        "verification": VerificationAgent,
        "infra.port": PortScanAgent,
        "infra.service": ServiceDetectAgent,
        "infra.tls": TLSScanAgent,
        "cloud.detect": CloudAgent,
        "cloud.s3": S3Agent,
        "cloud.gcp": GCPAgent,
        "cloud.azure": AzureAgent,
        "cloud.firebase": FirebaseAgent,
        "android.decompile": DecompileAgent,
        "android.webview": AndroidWebViewAgent,
        "android.storage": AndroidStorageAgent,
        "android.deeplinks": DeepLinkAgent,
    }

    cls = agent_map.get(agent_name)
    if cls:
        return cls()

    class StubAgent(BaseAgent):
        name = agent_name
        description = f"Stub for {agent_name}"

        async def execute(self, ctx) -> AgentResult:
            return AgentResult(
                agent_name=agent_name,
                status="completed",
                summary="⏭ Not yet implemented",
            )

    return StubAgent()


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    h, m = divmod(int(seconds), 3600)
    return f"{h}h {m}m"
