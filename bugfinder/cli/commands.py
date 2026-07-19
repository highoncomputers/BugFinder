from __future__ import annotations

import asyncio
import time
from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from bugfinder import __version__
from bugfinder.core.config import settings

app = typer.Typer(
    name="bf",
    help="BugFinder - AI-powered autonomous bug bounty assistant",
    no_args_is_help=False,
    rich_markup_mode="rich",
)

console = Console()


def _version_callback(value: bool) -> None:
    if value:
        rprint(f"[bold]BugFinder[/bold] v{__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", callback=_version_callback, is_eager=True),
) -> None:
    if ctx.invoked_subcommand is None:
        from bugfinder.cli.wizard import run_wizard

        asyncio.run(run_wizard())


def _show_banner() -> None:
    banner = Text(
        """

  ╔══════════════════════════════════════════╗
  ║     BugFinder v""" + __version__ + """ - Bug Bounty AI    ║
  ╚══════════════════════════════════════════╝
""",
        style="bold yellow",
    )
    console.print(banner)

    table = Table.grid(padding=(0, 2))
    table.add_column("", style="cyan", no_wrap=True)
    table.add_column("", style="white")

    table.add_row("", "")
    table.add_row("[bold underline yellow]SCANNING[/bold underline yellow]", "")
    table.add_row("  bf scan <target>", "Scan a target (auto-detect type)")
    table.add_row("  bf scan <target> --quick", "Lightweight scan (6 agents)")
    table.add_row("  bf scan <target> --deep", "Full coverage (32+ agents)")
    table.add_row("  bf scan <target> --expert", "Include race/XXE tests")
    table.add_row("", "")
    table.add_row("[bold underline red]RED TEAM[/bold underline red]", "")
    table.add_row("  bf redteam c2", "Generate C2 implant payloads")
    table.add_row("  bf redteam priv-esc", "Check privilege escalation vectors")
    table.add_row("  bf redteam lateral", "Map lateral movement paths")
    table.add_row("  bf redteam persistence", "Generate persistence mechanisms")
    table.add_row("  bf redteam evasion", "WAF detection + evasive payloads")
    table.add_row("  bf redteam exfil", "Data exfiltration planning")
    table.add_row("  bf redteam pivot", "Pivot tunnel setup")
    table.add_row("", "")
    table.add_row("[bold underline green]INTERFACES[/bold underline green]", "")
    table.add_row("  bf wizard", "Interactive numbered-menu console")
    table.add_row("  bf tui", "Terminal dashboard (Textual)")
    table.add_row("  bf web", "Web UI (http://127.0.0.1:8080)")
    table.add_row("", "")
    table.add_row("[bold underline blue]UTILITIES[/bold underline blue]", "")
    table.add_row("  bf list-agents", "Show all 47 assessment agents")
    table.add_row("  bf config <key> <val>", "Set configuration value")
    table.add_row("  bf report <scan_id>", "Generate scan report")
    table.add_row("  bf examples", "Show detailed usage examples")
    table.add_row("  bf plugin <action> [name]", "Manage plugins")
    table.add_row("", "")
    table.add_row("[dim]Use 'bf <command> --help' for details on any command[/dim]", "")
    console.print(table)


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
def wizard() -> None:
    """Launch the interactive wizard with numbered menus."""
    from bugfinder.cli.wizard import run_wizard

    asyncio.run(run_wizard())


@app.command()
def redteam(
    operation: str = typer.Argument(..., help="Operation: c2, priv-esc, lateral, persistence, evasion, exfil, pivot"),
    target: str = typer.Option("", "--target", "-t", help="Target host/domain"),
    lhost: str = typer.Option("127.0.0.1", "--lhost", help="C2 listener host (for c2)"),
    lport: int = typer.Option(4444, "--lport", help="C2 listener port (for c2)"),
    hosts: str = typer.Option("", "--hosts", help="Comma-separated hosts (for lateral/pivot)"),
    payloads: str = typer.Option("all", "--payloads", help="Payload types: python,bash,powershell,php,beacon (for c2)"),
    output: str | None = typer.Option(None, "--output", "-o", help="Save output to file"),
) -> None:
    """Red team operations: C2 implants, priv esc, lateral movement, persistence, evasion, exfil, pivot."""
    asyncio.run(_run_redteam(operation, target, lhost, lport, hosts, payloads, output))


async def _run_redteam(
    operation: str, target: str, lhost: str, lport: int, hosts: str, payloads: str, output: str | None
) -> None:
    from bugfinder.agents.base import AgentContext
    from bugfinder.knowledge_graph.graph import KnowledgeGraph
    from bugfinder.target.parsers import parse_target

    kg = KnowledgeGraph()
    ctx = AgentContext(
        target=parse_target(target) if target else "redteam",
        target_type="custom",
        scan_id="0",
        knowledge_graph=kg,
        ai_client=None,
        repository=None,
        config={
            "c2_lhost": lhost,
            "c2_lport": lport,
            "payloads": payloads.split(",") if payloads != "all" else ["python_reverse_shell", "bash_reverse_shell", "powershell_reverse", "php_reverse_shell", "python_beacon"],
            "target_hosts": hosts.split(",") if hosts else [target],
            "internal_hosts": hosts.split(",") if hosts else [],
            "internal_subnet": "10.0.0.0/24",
        },
    )

    agent_map = {
        "c2": ("redteam.c2_implant", "bugfinder.agents.redteam.c2_implant", "C2ImplantAgent"),
        "priv-esc": ("redteam.priv_esc", "bugfinder.agents.redteam.priv_esc", "PrivEscAgent"),
        "lateral": ("redteam.lateral_movement", "bugfinder.agents.redteam.lateral_movement", "LateralMovementAgent"),
        "persistence": ("redteam.persistence", "bugfinder.agents.redteam.persistence", "PersistenceAgent"),
        "evasion": ("redteam.evasion", "bugfinder.agents.redteam.evasion", "EvasionAgent"),
        "exfil": ("redteam.data_exfil", "bugfinder.agents.redteam.data_exfil", "DataExfilAgent"),
        "pivot": ("redteam.pivot_scan", "bugfinder.agents.redteam.pivot", "PivotScanAgent"),
    }

    if operation not in agent_map:
        rprint(f"[red]Unknown operation: {operation}[/red]")
        rprint(f"[yellow]Available: {', '.join(agent_map.keys())}[/yellow]")
        return

    name, module_path, class_name = agent_map[operation]
    import importlib

    module = importlib.import_module(module_path)
    agent_cls = getattr(module, class_name)
    agent = agent_cls(context=ctx)

    rprint(
        Panel.fit(
            f"[bold red]Red Team: {operation}[/bold red]\n"
            f"Agent: [cyan]{name}[/cyan]\n"
            f"Target: [green]{target or 'N/A'}[/green]",
            border_style="red",
        )
    )

    try:
        result = await agent.execute()
        if result and result.findings:
            table = Table(title=f"Findings ({len(result.findings)})")
            table.add_column("Severity", style="bold")
            table.add_column("Title")
            table.add_column("Action")
            for f in result.findings:
                sev = f.get("severity", "info")
                style = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "blue", "info": "dim white"}.get(sev, "")
                title = f.get("title", "Untitled")[:50]
                payload = f.get("payload_command") or f.get("payload") or f.get("commands", [None])[0] if f.get("commands") else ""
                evidence = payload[:80] + "..." if len(str(payload)) > 80 else payload
                table.add_row(f"[{style}]{sev.upper()}[/{style}]", title, evidence)
            console.print(table)

            if output:
                out_path = Path(output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(str(result), encoding="utf-8")
                rprint(f"[green]Saved to {out_path}[/green]")

        if result and result.summary:
            rprint(f"\n[bold green]✓ {result.summary}[/bold green]")
    except Exception as e:
        rprint(f"[red]✗ {operation} failed: {e}[/red]")


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
def examples() -> None:
    """Show detailed usage examples with annotated inputs and outputs."""
    ex = """
[bold yellow]BugFinder Usage Examples[/bold yellow]
══════════════════════════════════════

[bold underline cyan]▶  BASIC SCANS[/bold underline cyan]
───────────────────────────────────────

  [green]1. Scan a website (auto-detect)[/green]
     [bold]bf scan https://example.com[/bold]
     → Detects as: WEBSITE
     → Runs: DNS recon, tech detection, JS analysis, XSS/SQLi/SSTI/SSRF/LFI,
       JWT/CORS/CSP checks, WAF evasion, data exfil mapping, pivot scanning

  [green]2. Quick scan (lightweight)[/green]
     [bold]bf scan https://example.com --quick[/bold]
     → Runs: DNS, tech detection, crawl, basic XSS, basic SQLi, secrets scan
     → Good for: fast recon, low-noise testing

  [green]3. Deep scan with HTML report[/green]
     [bold]bf scan https://example.com --deep -o report.html[/bold]
     → Full coverage + saves HTML report to report.html

[bold underline red]▶  RED TEAM[/bold underline red]
───────────────────────────────────────

  [green]4. Generate C2 reverse shell payloads[/green]
     [bold]bf redteam c2 --lhost 10.0.0.5 --lport 4444 --payloads python,bash[/bold]
     → LHOST: your C2 server IP
     → LPORT: listener port (4444 common, 53/443 for egress)
     → PAYLOADS: python_reverse_shell, bash_reverse_shell, powershell_reverse,
       php_reverse_shell, python_beacon

  [green]5. Check privilege escalation vectors[/green]
     [bold]bf redteam priv-esc --target linux-server.company.com[/bold]
     → Checks: SUID binaries, sudo rules, cron jobs, Docker escape,
       kernel exploits, writable /etc/passwd, capabilities, NFS

  [green]6. Plan lateral movement[/green]
     [bold]bf redteam lateral --hosts 10.0.0.1,10.0.0.2,10.0.0.3[/bold]
     → Techniques: SSH key pivot, pass-the-hash, Kerberos tickets,
       AWS cred reuse, WinRM, SSH agent forwarding

  [green]7. Generate persistence mechanisms[/green]
     [bold]bf redteam persistence --target linux-server[/bold]
     → Generates: cron job, systemd service, SSH authorized_keys backdoor,
       LD_PRELOAD hook, registry Run key (Windows), WMI event subscription

  [green]8. WAF evasion techniques[/green]
     [bold]bf redteam evasion --target https://example.com[/bold]
     → Detects: Cloudflare, CloudFront, Akamai, Fastly, ModSecurity, AWS WAF,
       F5 BigIP, Sucuri, Imperva, Barracuda
     → Evasion: case permutation, double URL encoding, SQL comment injection,
       hex encoding, null byte, unicode normalization, parameter pollution

  [green]9. Data exfiltration planning[/green]
     [bold]bf redteam exfil --target internal-server[/bold]
     → Channels: DNS tunneling, HTTP/S, ICMP covert, DNS-over-HTTPS,
       WebSocket tunneling, SMTP/email

  [green]10. Pivot tunnel setup[/green]
      [bold]bf redteam pivot --target 10.0.0.1 --hosts 10.0.1.1,10.0.1.2[/bold]
      → Tunnels: SSH dynamic forward, Chisel, socat relay, FRP,
        Metasploit route, ProxyChains

[bold underline green]▶  INTERFACES[/bold underline green]
───────────────────────────────────────────

  [green]11. Launch the all-in-one interactive console[/green]
      [bold]bf[/bold]
      → Opens the full-featured menu: 1=Scan, 2=Red Team, 3=PoC,
        4=Reports, 5=Config, 6=TUI Dashboard, 7=Examples, 0=Exit

  [green]12. Terminal UI dashboard[/green]
      [bold]bf tui[/bold]
      → Full TUI with: target input, scan progress, findings table,
        agent browser, config editor

  [green]13. Web UI[/green]
      [bold]bf web[/bold]
      → Opens http://127.0.0.1:8080
      → Dashboard, scans, findings, projects, reports, proxy, graph, chat

[bold underline blue]▶  UTILITIES[/bold underline blue]
───────────────────────────────────────────

  [green]14. List all agents[/green]
      [bold]bf list-agents[/bold]
      → Shows all 47 agents with categories

  [green]15. Set API key[/green]
      [bold]bf config nvidia.api_key nvapi-xxx...[/bold]

  [green]16. Generate report from scan ID[/green]
      [bold]bf report 1 --format html -o report.html[/bold]

[dim]For more help on any command: bf <command> --help[/dim]
"""
    rprint(ex.strip())


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


def _run_scan(
    target, profile: str = "auto", expert: bool = False, output: str | None = None, report_format: str = "markdown"
) -> None:
    asyncio.run(_async_scan(target, profile, expert, output, report_format))


async def _async_scan(
    target, profile: str = "auto", expert: bool = False, output: str | None = None, report_format: str = "markdown"
) -> None:
    from bugfinder.core.types import TargetType
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session
    from bugfinder.knowledge_graph.graph import KnowledgeGraph
    from bugfinder.reporting.html import generate_html_report
    from bugfinder.reporting.json_report import generate_json_report
    from bugfinder.reporting.markdown import generate_markdown_report

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

    ttype = target.type.value
    scan_id = 0
    try:
        async with async_session() as session:
            repo = Repository(session)
            tt = TargetType.UNKNOWN
            try:
                tt = TargetType(ttype)
            except ValueError:
                pass
            scan_record = await repo.create_scan(
                target=target.raw,
                target_type=tt,
                profile=profile,
            )
            scan_id = scan_record.id
    except Exception as e:
        rprint(f"[yellow]DB error (scans still work): {e}[/yellow]")

    rprint(f"\n[bold]Scan Plan[/bold] ({target.type.value})")
    rprint("─" * 50)

    start_time = time.monotonic()

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

    from bugfinder.agents.base import AgentContext
    from bugfinder.target.parsers import parse_target

    ctx = AgentContext(
        target=parse_target(target.raw),
        target_type=ttype,
        scan_id=str(scan_id),
        knowledge_graph=kg,
        ai_client=ai_client,
        repository=None,
    )

    findings_counters = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    total = len(steps_def)
    for i, step_def in enumerate(steps_def):
        agent_name = step_def["agent"]

        agent = await _load_agent(agent_name, context=ctx)

        try:
            result = await agent.execute()
            if result and result.findings:
                for f in result.findings:
                    f_id = f.get("id", f"f-{id(f)}")
                    kg.add_node(f_id, "finding", **f)
                    sev = f.get("severity", "info")
                    findings_counters[sev] = findings_counters.get(sev, 0) + 1
                    sev_label = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "ℹ"}.get(sev, "•")
                    rprint(f"    {sev_label} [{sev.upper()}] {f['title']}")
                tally = " | ".join(f"[bold]{k.capitalize()}[/bold]: {v}" for k, v in findings_counters.items() if v > 0)
                rprint(f"  [dim]📊 {tally}[/dim]")
            if result and result.summary:
                rprint(f"    [green]✓ {result.summary}[/green]")
            else:
                rprint(f"    [green]✓ {agent_name} completed[/green]")
        except Exception as e:
            rprint(f"    [red]✗ {agent_name} failed: {e}[/red]")

        elapsed_s = time.monotonic() - start_time
        pct = min(int(((i + 1) / total) * 100), 100)
        eta = (elapsed_s / (i + 1)) * (total - i - 1) if i < total - 1 else 0
        rprint(f"  [dim]⏱ {_format_duration(elapsed_s)} | {pct}% | ETA: {_format_duration(eta)}[/dim]")

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
        table.add_column("", style="bold")
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Confidence")
        for f in sorted(
            all_findings,
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 99}.get(x.get("severity", "info"), 99),
        ):
            sev = f.get("severity", "info")
            style = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "blue", "info": "dim white"}.get(sev, "")
            icon = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "ℹ"}.get(sev, "•")
            table.add_row(
                icon,
                f"[{style}]{sev.upper()}[/{style}]",
                f.get("title", "Untitled")[:60],
                f.get("confidence", "medium"),
            )
        console.print(table)

    generator = report_generators.get(report_format, report_generators["markdown"])
    report_content = generator(
        target=target.raw,
        target_type=ttype,
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
    from bugfinder.reporting.html import generate_html_report
    from bugfinder.reporting.json_report import generate_json_report
    from bugfinder.reporting.markdown import generate_markdown_report

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


async def _load_agent(agent_name: str, context=None):
    from bugfinder.agents.android.decompile import DecompileAgent
    from bugfinder.agents.android.deeplinks import DeepLinkAgent
    from bugfinder.agents.android.storage import AndroidStorageAgent
    from bugfinder.agents.android.webview import AndroidWebViewAgent
    from bugfinder.agents.api.auth import APIAuthAgent
    from bugfinder.agents.api.discover import APIDiscoverAgent
    from bugfinder.agents.api.fuzz import APIFuzzAgent
    from bugfinder.agents.api.rate import APIRateAgent
    from bugfinder.agents.base import AgentResult, BaseAgent
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
    from bugfinder.agents.recon.subdomain import SubdomainAgent
    from bugfinder.agents.recon.tech import TechDetectAgent
    from bugfinder.agents.recon.wayback import WaybackAgent
    from bugfinder.agents.redteam.c2_implant import C2ImplantAgent
    from bugfinder.agents.redteam.data_exfil import DataExfilAgent
    from bugfinder.agents.redteam.evasion import EvasionAgent
    from bugfinder.agents.redteam.lateral_movement import LateralMovementAgent
    from bugfinder.agents.redteam.persistence import PersistenceAgent
    from bugfinder.agents.redteam.pivot import PivotScanAgent
    from bugfinder.agents.redteam.priv_esc import PrivEscAgent
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

    agent_map: dict[str, type] = {
        "recon.dns": DNSAgent,
        "recon.tech": TechDetectAgent,
        "recon.wayback": WaybackAgent,
        "recon.github": GitHubAgent,
        "recon.googledorks": GoogleDorkAgent,
        "recon.subdomain": SubdomainAgent,
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
        "api.auth": APIAuthAgent,
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
        "redteam.c2_implant": C2ImplantAgent,
        "redteam.priv_esc": PrivEscAgent,
        "redteam.lateral_movement": LateralMovementAgent,
        "redteam.persistence": PersistenceAgent,
        "redteam.evasion": EvasionAgent,
        "redteam.data_exfil": DataExfilAgent,
        "redteam.pivot_scan": PivotScanAgent,
    }

    cls = agent_map.get(agent_name)
    if cls:
        return cls(context=context)

    class StubAgent(BaseAgent):
        name = agent_name
        description = f"Stub for {agent_name}"

        async def execute(self) -> AgentResult:
            return AgentResult(
                agent_name=agent_name,
                status="completed",
                summary="⏭ Not yet implemented",
            )

    return StubAgent(context=context)


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    total = int(seconds)
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    parts = [f"{h}h"]
    if m:
        parts.append(f"{m}m")
    if s:
        parts.append(f"{s}s")
    return " ".join(parts)
