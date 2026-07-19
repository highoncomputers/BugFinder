from __future__ import annotations

import asyncio
import sys

from rich import print as rprint
from rich.console import Console
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

from bugfinder import __version__

console = Console()

REDTEAM_OPS = {
    "1": ("C2 Implant", "c2", "Generate C2 reverse shell payloads", {
        "lhost": {"prompt": "Listener host (LHOST)", "default": "10.0.0.5", "example": "10.0.0.5"},
        "lport": {"prompt": "Listener port (LPORT)", "default": "4444", "example": "4444"},
        "payloads": {"prompt": "Payload types (comma-separated)", "default": "python,bash", "example": "python,bash,powershell"},
    }),
    "2": ("Privilege Escalation", "priv-esc", "Check privilege escalation vectors", {
        "target": {"prompt": "Target host", "default": "", "example": "linux-server.company.com"},
    }),
    "3": ("Lateral Movement", "lateral", "Map lateral movement paths", {
        "hosts": {"prompt": "Target hosts (comma-separated)", "default": "", "example": "10.0.0.1,10.0.0.2,10.0.0.3"},
    }),
    "4": ("Persistence", "persistence", "Generate persistence mechanisms", {
        "target": {"prompt": "Target host", "default": "", "example": "linux-server"},
    }),
    "5": ("WAF Evasion", "evasion", "WAF detection + evasive payloads", {
        "target": {"prompt": "Target URL", "default": "", "example": "https://example.com"},
    }),
    "6": ("Data Exfiltration", "exfil", "Data exfiltration planning", {
        "target": {"prompt": "Target host", "default": "", "example": "internal-server"},
    }),
    "7": ("Pivot Tunnel", "pivot", "Pivot tunnel setup", {
        "target": {"prompt": "Target host", "default": "", "example": "10.0.0.1"},
        "hosts": {"prompt": "Internal hosts (comma-separated)", "default": "", "example": "10.0.1.1,10.0.1.2"},
    }),
}

SCAN_PROFILES = {
    "1": ("Quick Scan", "quick", "6 agents: DNS, tech detection, crawl, basic XSS/SQLi, secrets"),
    "2": ("Deep Scan", "deep", "Full coverage (32+ agents)"),
    "3": ("Expert Scan", "expert", "Deep + race condition + XXE injection"),
    "4": ("Auto Scan", "auto", "Auto-detect profile based on target"),
}


def _show_header(title: str) -> None:
    console.clear()
    banner = Text(f"\n  BugFinder v{__version__}", style="bold yellow")
    console.print(banner)
    console.print(f"  [bold cyan]{'=' * 40}[/bold cyan]")
    console.print(f"  [bold white]{title}[/bold white]")
    console.print(f"  [bold cyan]{'=' * 40}[/bold cyan]\n")


def _show_menu(title: str, options: dict[str, tuple[str, str, str]], extra: str = "") -> str:
    _show_header(title)
    table = Table.grid(padding=(0, 3))
    table.add_column("", style="cyan", no_wrap=True)
    table.add_column("", style="white")
    table.add_column("", style="dim white")
    for key, (label, _desc, summary) in options.items():
        table.add_row(f"  [{key}]", label, f"  {summary}")
    table.add_row("", "", "")
    table.add_row("  [0]", "Back / Exit", "")
    if extra:
        table.add_row("", "", "")
        table.add_row("", extra, "")
    console.print(table)
    console.print()
    return Prompt.ask("[bold yellow]Enter choice", choices=list(options.keys()) + ["0"], default="0")


def _run_scan(target: str, profile: str) -> None:
    with console.status(f"[bold green]Running {profile} scan on {target}..."):
        try:
            from bugfinder.target.detector import detect_target_type, normalize_target
            from bugfinder.target.parsers import Target

            target_type = detect_target_type(target)
            normalized = normalize_target(target)
            t = Target(target, target_type, normalized=normalized)

            from bugfinder.cli.commands import _async_scan

            asyncio.run(_async_scan(t, profile=profile))
        except Exception as e:
            rprint(f"[red]Scan failed: {e}[/red]")


async def _run_redteam_op(operation: str, params: dict) -> None:
    from bugfinder.cli.commands import _run_redteam

    await _run_redteam(
        operation=operation,
        target=params.get("target", ""),
        lhost=params.get("lhost", "127.0.0.1"),
        lport=int(params.get("lport", "4444")),
        hosts=params.get("hosts", ""),
        payloads=params.get("payloads", "all"),
        output=params.get("output", None),
    )


def _collect_params(fields: dict) -> dict:
    params = {}
    for key, field in fields.items():
        prompt_text = f"[bold]{field['prompt']}[/bold]"
        if field.get("example"):
            prompt_text += f" [dim](e.g. {field['example']})[/dim]"
        default = field.get("default", "")
        val = Prompt.ask(prompt_text, default=default) if default else Prompt.ask(prompt_text)
        params[key] = val
    return params


def _scan_menu() -> None:
    while True:
        choice = _show_menu(
            "SCAN TARGET",
            SCAN_PROFILES,
            extra="[dim]Example: bf scan https://example.com --deep[/dim]",
        )
        if choice is None or choice == "0":
            return
        profile_info = SCAN_PROFILES.get(choice)
        if not profile_info:
            continue
        _label, profile, _desc = profile_info
        target = Prompt.ask("[bold]Enter target URL/IP/domain")
        if target.strip():
            _run_scan(target.strip(), profile)


def _redteam_menu() -> None:
    while True:
        choice = _show_menu(
            "RED TEAM OPERATIONS",
            REDTEAM_OPS,
            extra="[dim]Example: bf redteam c2 --lhost 10.0.0.5 --lport 4444[/dim]",
        )
        if choice is None or choice == "0":
            return
        op_info = REDTEAM_OPS.get(choice)
        if not op_info:
            continue
        label, operation, _desc, fields = op_info
        _show_header(f"RED TEAM > {label}")
        rprint(f"  [dim]{_desc}[/dim]\n")
        params = _collect_params(fields)
        rprint()
        if Confirm.ask(f"[bold yellow]Run {label}?", default=True):
            asyncio.run(_run_redteam_op(operation, params))
            Prompt.ask("\n[dim]Press Enter to continue[/dim]")


def _poc_menu() -> None:
    _show_header("PROOF OF CONCEPT GENERATOR")
    poc_types = {
        "1": ("XSS PoC", "Generate cross-site scripting PoC", "xss"),
        "2": ("SQLi PoC", "Generate SQL injection PoC", "sqli"),
        "3": ("SSRF PoC", "Generate SSRF PoC", "ssrf"),
        "4": ("LFI PoC", "Generate LFI PoC", "lfi"),
        "5": ("SSTI PoC", "Generate SSTI PoC", "ssti"),
    }
    table = Table.grid(padding=(0, 3))
    table.add_column("", style="cyan", no_wrap=True)
    table.add_column("", style="white")
    table.add_column("", style="dim white")
    for key, (label, desc, _) in poc_types.items():
        table.add_row(f"  [{key}]", label, f"  {desc}")
    table.add_row("", "", "")
    table.add_row("  [0]", "Back", "")
    console.print(table)
    console.print()

    choice = Prompt.ask("[bold yellow]Enter choice", choices=list(poc_types.keys()) + ["0"], default="0")
    if choice == "0":
        return

    poc_info = poc_types.get(choice)
    if not poc_info:
        return
    label, _desc, vuln_type = poc_info
    _show_header(f"PoC > {label}")

    target = Prompt.ask("[bold]Target URL", default="https://example.com")
    param = Prompt.ask("[bold]Vulnerable parameter", default="q")

    with console.status(f"[bold green]Generating {vuln_type} PoC..."):
        try:
            from bugfinder.engine.poc_generator import PoCGenerator

            generator_map = {
                "xss": PoCGenerator._xss_poc,
                "ssti": PoCGenerator._ssti_poc,
                "ssrf": PoCGenerator._ssrf_poc,
            }
            generator = generator_map.get(vuln_type)
            if generator:
                poc = generator(target, f"{vuln_type} test on {param}")
                rprint("\n[bold green]PoC Generated[/bold green]")
                rprint(f"  [bold]Vulnerability:[/bold] {poc.vulnerability}")
                rprint(f"  [bold]Curl:[/bold] {poc.curl_command}")
            else:
                rprint(f"[yellow]PoC generator for {vuln_type} not yet implemented[/yellow]")
        except Exception as e:
            rprint(f"[red]PoC generation failed: {e}[/red]")

    Prompt.ask("\n[dim]Press Enter to continue[/dim]")


def _reports_menu() -> None:
    _show_header("REPORTS")
    rprint("  1. Generate report from scan ID")
    rprint("  2. View recent scans")
    rprint("  3. Export all findings")
    rprint("  0. Back\n")

    choice = Prompt.ask("[bold yellow]Enter choice", choices=["1", "2", "3", "0"], default="0")
    if choice == "0":
        return

    if choice == "1":
        scan_id = IntPrompt.ask("[bold]Scan ID", default=1)
        fmt = Prompt.ask("[bold]Report format", choices=["markdown", "html", "json"], default="markdown")
        output = Prompt.ask("[bold]Output path (optional)", default="")
        from bugfinder.cli.commands import _generate_report

        with console.status(f"[bold green]Generating {fmt} report for scan {scan_id}..."):
            _generate_report(scan_id, fmt, output or None)

    elif choice == "2":
        rprint("[yellow]Recent scans: feature requires database integration[/yellow]")

    elif choice == "3":
        rprint("[yellow]Export: feature requires database integration[/yellow]")

    Prompt.ask("\n[dim]Press Enter to continue[/dim]")


def _config_menu() -> None:
    _show_header("CONFIGURATION")
    rprint("  1. Set NVIDIA API key")
    rprint("  2. Toggle beginner mode")
    rprint("  3. View current config")
    rprint("  0. Back\n")

    choice = Prompt.ask("[bold yellow]Enter choice", choices=["1", "2", "3", "0"], default="0")
    if choice == "0":
        return

    from bugfinder.core.config import settings

    if choice == "1":
        key = Prompt.ask("[bold]NVIDIA API Key", password=True)
        if key:
            settings.nvidia_api_key = key
            rprint("[green]NVIDIA API key saved[/green]")

    elif choice == "2":
        val = Confirm.ask("[bold]Enable beginner mode?", default=False)
        settings.beginner_mode = val
        rprint(f"[green]Beginner mode = {val}[/green]")

    elif choice == "3":
        rprint(f"\n  [bold]AI enabled:[/bold] {settings.ai_enabled}")
        rprint(f"  [bold]NVIDIA key set:[/bold] {'Yes' if settings.nvidia_api_key else 'No'}")
        rprint(f"  [bold]Beginner mode:[/bold] {settings.beginner_mode}")
        rprint(f"  [bold]Reports path:[/bold] {settings.reports_path}")

    Prompt.ask("\n[dim]Press Enter to continue[/dim]")


def _examples_menu() -> None:
    _show_header("USAGE EXAMPLES")
    examples = """
[bold yellow]Basic Scans:[/bold yellow]
  bf scan https://example.com          Auto-detect + full scan
  bf scan https://example.com --quick  Lightweight (6 agents)
  bf scan https://example.com --deep   Full coverage (32+ agents)
  bf scan app.apk                      Android APK analysis
  bf scan 192.168.1.1                  Infrastructure scan

[bold yellow]Red Team:[/bold yellow]
  bf redteam c2 --lhost 10.0.0.5       Generate C2 payloads
  bf redteam priv-esc --target HOST    Priv esc checks
  bf redteam lateral --hosts LIST      Lateral movement
  bf redteam persistence --target HOST Persistence mechanisms
  bf redteam evasion --target URL      WAF evasion
  bf redteam exfil --target HOST       Data exfiltration
  bf redteam pivot --target HOST       Pivot tunnels

[bold yellow]Interfaces:[/bold yellow]
  bf wizard   Interactive menu system
  bf tui      Terminal dashboard
  bf web      Web UI (http://127.0.0.1:8080)

[bold yellow]Utilities:[/bold yellow]
  bf list-agents        Show all 47 agents
  bf config KEY VAL     Set config value
  bf report ID          Generate report
  bf examples           This help
"""
    rprint(examples.strip())
    Prompt.ask("\n[dim]Press Enter to continue[/dim]")


async def run_wizard() -> None:
    while True:
        _show_header("MAIN MENU")
        table = Table.grid(padding=(0, 3))
        table.add_column("", style="cyan", no_wrap=True)
        table.add_column("", style="white bold")
        table.add_column("", style="dim white")
        table.add_row("  [1]", "Scan Target", "  Run security scan")
        table.add_row("  [2]", "Red Team", "  C2, priv-esc, lateral movement, persistence, evasion, exfil, pivot")
        table.add_row("  [3]", "PoC Generator", "  Generate proof-of-concept exploits")
        table.add_row("  [4]", "Reports", "  Generate & view scan reports")
        table.add_row("  [5]", "Configuration", "  Set API keys, toggle modes")
        table.add_row("  [6]", "Examples", "  View usage examples")
        table.add_row("", "", "")
        table.add_row("  [0]", "Exit", "  Quit BugFinder")
        console.print(table)
        console.print()

        choice = Prompt.ask("[bold yellow]Enter choice", choices=["1", "2", "3", "4", "5", "6", "0"], default="0")

        if choice == "0":
            _show_header("GOODBYE")
            rprint("  [yellow]Exiting BugFinder. Happy hunting![/yellow]\n")
            sys.exit(0)
        elif choice == "1":
            _scan_menu()
        elif choice == "2":
            _redteam_menu()
        elif choice == "3":
            _poc_menu()
        elif choice == "4":
            _reports_menu()
        elif choice == "5":
            _config_menu()
        elif choice == "6":
            _examples_menu()


if __name__ == "__main__":
    asyncio.run(run_wizard())
