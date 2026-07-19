from __future__ import annotations

import time
from pathlib import Path

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    ProgressBar,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from bugfinder import __version__


class WelcomeScreen(Screen):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "start_scan", "Scan"),
        Binding("1", "switch_screen('welcome')", "Home"),
        Binding("2", "switch_screen('progress')", "Progress"),
        Binding("3", "switch_screen('results')", "Results"),
        Binding("4", "switch_screen('agents')", "Agents"),
        Binding("5", "switch_screen('config')", "Config"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            Static("", id="spacer-top"),
            Static(Text("BugFinder", style="bold yellow"), id="app-title"),
            Static(Text(f"v{__version__}  AI-Powered Bug Bounty Assistant", style="dim white"), id="app-subtitle"),
            Static("", id="spacer-1"),
            Input(placeholder="Enter target: URL, IP, domain, APK path...", id="target-input"),
            Static("", id="spacer-2"),
            Horizontal(
                Button("Quick Scan", variant="primary", id="quick", classes="scan-btn"),
                Button("Deep Scan", variant="default", id="deep", classes="scan-btn"),
                Button("Expert Mode", variant="warning", id="expert", classes="scan-btn"),
                classes="button-row",
            ),
            Static("", id="spacer-3"),
            Static("[bold]Recent Scans[/bold]", id="recent-header"),
            ListView(id="recent-list"),
            id="main-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#target-input", Input).focus()
        self._load_recent()

    def _load_recent(self) -> None:
        recent = getattr(self.app, "_recent_scans", [])
        lv = self.query_one("#recent-list", ListView)
        lv.clear()
        if not recent:
            lv.append(ListItem(Label("[dim]No recent scans[/dim]")))
        for r in recent[-10:]:
            lv.append(ListItem(Label(f"  {r}")))

    async def action_start_scan(self) -> None:
        target = self.query_one("#target-input", Input).value.strip()
        if not target:
            self.notify("Please enter a target", severity="warning", timeout=3)
            return
        self.app._scan_target = target
        self.app._scan_mode = "quick"
        self.app.switch_screen("progress")
        self.app.run_scan()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        target = self.query_one("#target-input", Input).value.strip()
        if not target:
            self.notify("Please enter a target", severity="warning", timeout=3)
            return
        self.app._scan_target = target
        self.app._scan_mode = event.button.id or "quick"
        self.app.switch_screen("progress")
        self.app.run_scan()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.value.strip():
            self.app._scan_target = event.value.strip()
            self.app._scan_mode = "quick"
            self.app.switch_screen("progress")
            self.app.run_scan()

    def action_switch_screen(self, screen: str) -> None:
        self.app.switch_screen(screen)


class ScanProgressScreen(Screen):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("h", "go_home", "Home"),
        Binding("r", "go_results", "Results"),
        Binding("1", "switch_screen('welcome')", "Home"),
        Binding("2", "switch_screen('progress')", "Progress"),
        Binding("3", "switch_screen('results')", "Results"),
        Binding("4", "switch_screen('agents')", "Agents"),
        Binding("5", "switch_screen('config')", "Config"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            Static("[bold yellow]Scan in Progress[/bold yellow]", id="progress-title"),
            Static("", id="progress-target"),
            ProgressBar(total=100, show_eta=True, id="scan-progress"),
            Static("", id="progress-status"),
            RichLog(id="progress-log", highlight=True, markup=True, max_lines=100),
            id="progress-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        target = getattr(self.app, "_scan_target", "unknown")
        mode = getattr(self.app, "_scan_mode", "quick")
        self.query_one("#progress-target", Static).update(
            f"  [cyan]{target}[/cyan]  [dim]({mode})[/dim]"
        )

    def action_go_home(self) -> None:
        self.app.switch_screen("welcome")

    def action_go_results(self) -> None:
        self.app.switch_screen("results")

    def action_switch_screen(self, screen: str) -> None:
        self.app.switch_screen(screen)

    def update_progress(self, pct: int, status: str) -> None:
        self.query_one("#scan-progress", ProgressBar).progress = pct
        self.query_one("#progress-status", Static).update(f"  [bold]{status}[/bold]")

    def append_log(self, msg: str) -> None:
        self.query_one("#progress-log", RichLog).write(msg)


class ScanResultsScreen(Screen):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("h", "go_home", "Home"),
        Binding("s", "start_new", "New Scan"),
        Binding("1", "switch_screen('welcome')", "Home"),
        Binding("2", "switch_screen('progress')", "Progress"),
        Binding("3", "switch_screen('results')", "Results"),
        Binding("4", "switch_screen('agents')", "Agents"),
        Binding("5", "switch_screen('config')", "Config"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            Static("[bold green]Scan Results[/bold green]", id="results-title"),
            Static("", id="results-summary"),
            TabbedContent(
                TabPane("Findings", RichLog(id="results-findings", highlight=True, markup=True)),
                TabPane("Assets", RichLog(id="results-assets", highlight=True, markup=True)),
                id="results-tabs",
            ),
            id="results-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        findings = getattr(self.app, "_scan_findings", [])
        summary = getattr(self.app, "_scan_summary", "No results yet")
        self.query_one("#results-summary", Static).update(f"  [bold]{summary}[/bold]")
        rl = self.query_one("#results-findings", RichLog)
        if findings:
            for f in findings:
                sev = f.get("severity", "info")
                style = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "blue", "info": "dim white"}.get(sev, "")
                rl.write(f"[{style}][{sev.upper()}][/{style}] {f.get('title', 'Untitled')}")
        else:
            rl.write("[dim]No findings to display[/dim]")

    def action_go_home(self) -> None:
        self.app.switch_screen("welcome")

    def action_start_new(self) -> None:
        self.app.switch_screen("welcome")

    def action_switch_screen(self, screen: str) -> None:
        self.app.switch_screen(screen)


class AgentsScreen(Screen):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("h", "go_home", "Home"),
        Binding("1", "switch_screen('welcome')", "Home"),
        Binding("2", "switch_screen('progress')", "Progress"),
        Binding("3", "switch_screen('results')", "Results"),
        Binding("4", "switch_screen('agents')", "Agents"),
        Binding("5", "switch_screen('config')", "Config"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            Static("[bold cyan]Available Agents[/bold cyan]", id="agents-title"),
            Input(placeholder="Filter agents...", id="agent-filter"),
            ListView(id="agent-list"),
            id="agents-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_agents()

    def _refresh_agents(self, filter_text: str = "") -> None:
        try:
            from bugfinder.planner.rule_planner import TARGET_PLANS

            all_agents: set[str] = set()
            for plans in TARGET_PLANS.values():
                for p in plans:
                    all_agents.add(p["agent"])

            lv = self.query_one("#agent-list", ListView)
            lv.clear()
            for agent in sorted(all_agents):
                if filter_text.lower() in agent.lower():
                    lv.append(ListItem(Label(f"  {agent}")))
        except Exception:
            pass

    def on_input_changed(self, event: Input.Changed) -> None:
        self._refresh_agents(event.value)

    def action_go_home(self) -> None:
        self.app.switch_screen("welcome")

    def action_switch_screen(self, screen: str) -> None:
        self.app.switch_screen(screen)


class ConfigScreen(Screen):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("h", "go_home", "Home"),
        Binding("s", "save", "Save"),
        Binding("1", "switch_screen('welcome')", "Home"),
        Binding("2", "switch_screen('progress')", "Progress"),
        Binding("3", "switch_screen('results')", "Results"),
        Binding("4", "switch_screen('agents')", "Agents"),
        Binding("5", "switch_screen('config')", "Config"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            Static("[bold blue]Configuration[/bold blue]", id="config-title"),
            Static("", id="config-status"),
            Static("[bold]NVIDIA API Key[/bold]", classes="config-label"),
            Input(placeholder="nvapi-...", id="config-api-key", password=True),
            Static("", id="config-spacer-1"),
            Static("[bold]Beginner Mode[/bold]", classes="config-label"),
            Horizontal(
                Button("On", id="beginner-on", classes="config-btn"),
                Button("Off", id="beginner-off", classes="config-btn"),
                classes="button-row",
            ),
            Static("", id="config-spacer-2"),
            Static("[bold]Reports Directory[/bold]", classes="config-label"),
            Input(placeholder="/path/to/reports", id="config-reports-path"),
            Static("", id="config-spacer-3"),
            Static("[dim]Key bindings: q=quit, h=home, s=save, 1-5=screens[/dim]", id="config-hint"),
            id="config-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        from bugfinder.core.config import settings
        if settings.nvidia_api_key:
            self.query_one("#config-api-key", Input).value = "********"
        if settings.reports_path:
            self.query_one("#config-reports-path", Input).value = str(settings.reports_path)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        from bugfinder.core.config import settings
        if event.button.id == "beginner-on":
            settings.beginner_mode = True
            self.notify("Beginner mode ON", severity="information", timeout=2)
        elif event.button.id == "beginner-off":
            settings.beginner_mode = False
            self.notify("Beginner mode OFF", severity="information", timeout=2)

    def action_save(self) -> None:
        from bugfinder.core.config import settings
        api_key = self.query_one("#config-api-key", Input).value
        if api_key and api_key != "********":
            settings.nvidia_api_key = api_key
        reports_path = self.query_one("#config-reports-path", Input).value
        if reports_path:
            settings.reports_path = Path(reports_path)
        self.notify("Configuration saved", severity="information", timeout=2)

    def action_go_home(self) -> None:
        self.app.switch_screen("welcome")

    def action_switch_screen(self, screen: str) -> None:
        self.app.switch_screen(screen)


class BugFinderTUI(App):
    TITLE = "BugFinder"
    SUB_TITLE = f"v{__version__} - AI-Powered Bug Bounty Assistant"
    CSS_PATH = "app.tcss"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("h", "go_home", "Home"),
        Binding("s", "start_scan", "Scan"),
        Binding("r", "show_results", "Results"),
        Binding("a", "show_agents", "Agents"),
        Binding("c", "show_config", "Config"),
        Binding("1", "screen_welcome", "1"),
        Binding("2", "screen_progress", "2"),
        Binding("3", "screen_results", "3"),
        Binding("4", "screen_agents", "4"),
        Binding("5", "screen_config", "5"),
    ]

    _scan_target: str = ""
    _scan_mode: str = "quick"
    _scan_findings: list = []
    _scan_summary: str = ""
    _recent_scans: list[str] = []

    SCREENS = {
        "welcome": WelcomeScreen,
        "progress": ScanProgressScreen,
        "results": ScanResultsScreen,
        "agents": AgentsScreen,
        "config": ConfigScreen,
    }

    def on_mount(self) -> None:
        self.push_screen("welcome")

    def switch_screen(self, screen_name: str) -> None:
        if screen_name in self.SCREENS:
            self.push_screen(screen_name)

    def action_go_home(self) -> None:
        self.switch_screen("welcome")

    def action_start_scan(self) -> None:
        target = getattr(self, "_scan_target", "")
        if not target:
            self.switch_screen("welcome")
            return
        self.switch_screen("progress")
        self.run_scan()

    def action_show_results(self) -> None:
        self.switch_screen("results")

    def action_show_agents(self) -> None:
        self.switch_screen("agents")

    def action_show_config(self) -> None:
        self.switch_screen("config")

    def action_screen_welcome(self) -> None:
        self.switch_screen("welcome")

    def action_screen_progress(self) -> None:
        self.switch_screen("progress")

    def action_screen_results(self) -> None:
        self.switch_screen("results")

    def action_screen_agents(self) -> None:
        self.switch_screen("agents")

    def action_screen_config(self) -> None:
        self.switch_screen("config")

    @work(exclusive=True)
    async def run_scan(self) -> None:
        target = self._scan_target
        mode = self._scan_mode

        progress_screen = self.SCREENS["progress"]
        progress_screen.append_log(f"[bold cyan]Starting {mode} scan on {target}[/bold cyan]")

        try:
            from bugfinder.target.detector import detect_target_type, normalize_target
            from bugfinder.target.parsers import Target

            target_type = detect_target_type(target)
            normalized = normalize_target(target)
            t = Target(target, target_type, normalized=normalized)

            from bugfinder.agents.base import AgentContext
            from bugfinder.cli.commands import _load_agent
            from bugfinder.knowledge_graph.graph import KnowledgeGraph

            kg = KnowledgeGraph()

            if mode == "quick":
                steps = [
                    {"agent": "recon.dns", "rationale": "DNS reconnaissance"},
                    {"agent": "recon.tech", "rationale": "Technology detection"},
                    {"agent": "web.crawler", "rationale": "Web crawling"},
                    {"agent": "web.xss", "rationale": "XSS scanning"},
                    {"agent": "web.sqli", "rationale": "SQL injection scanning"},
                    {"agent": "secrets.scan", "rationale": "Secret scanning"},
                ]
            else:
                from bugfinder.core.types import TargetType
                from bugfinder.planner.rule_planner import TARGET_PLANS

                tt = TargetType.UNKNOWN
                try:
                    tt = TargetType(t.type.value)
                except ValueError:
                    pass
                steps = list(TARGET_PLANS.get(tt, []))
                if mode == "expert":
                    steps += [
                        {"agent": "web.race", "rationale": "Race condition testing"},
                        {"agent": "web.xxe", "rationale": "XXE injection testing"},
                    ]

            ctx = AgentContext(
                target=t,
                target_type=t.type.value,
                scan_id="tui-0",
                knowledge_graph=kg,
                ai_client=None,
                repository=None,
            )

            findings = []
            total = len(steps)
            start_time = time.monotonic()

            for i, step in enumerate(steps):
                pct = int(((i) / total) * 100)
                progress_screen.update_progress(pct, step["rationale"])
                progress_screen.append_log(f"[dim]→ {step['rationale']} ({step['agent']})[/dim]")

                agent = await _load_agent(step["agent"], context=ctx)
                try:
                    result = await agent.execute()
                    if result and result.findings:
                        for f in result.findings:
                            findings.append(f)
                            sev = f.get("severity", "info")
                            icon = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "ℹ"}.get(sev, "•")
                            progress_screen.append_log(f"  {icon} [{sev.upper()}] {f['title']}")
                    if result and result.summary:
                        progress_screen.append_log(f"  [green]✓ {result.summary}[/green]")
                    else:
                        progress_screen.append_log(f"  [green]✓ {step['agent']} completed[/green]")
                except Exception as e:
                    progress_screen.append_log(f"  [red]✗ {step['agent']} failed: {e}[/red]")

                elapsed = time.monotonic() - start_time
                progress_screen.append_log(f"  [dim]⏱ {elapsed:.0f}s | {pct}%[/dim]")

            progress_screen.update_progress(100, "Scan complete")
            progress_screen.append_log("[bold green]✓ Scan completed successfully[/bold green]")

            self._scan_findings = findings
            self._scan_summary = f"{len(findings)} findings in {total} steps"
            self._recent_scans.append(f"{target} ({mode}) - {len(findings)} findings")

            self.SCREENS["results"].refresh()
            self.switch_screen("results")

        except Exception as e:
            progress_screen.append_log(f"[bold red]✗ Scan failed: {e}[/bold red]")
            self._scan_summary = f"Scan failed: {e}"
