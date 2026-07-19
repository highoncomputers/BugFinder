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
        Binding("q", "app.quit", "Quit"),
        Binding("s", "app.start_scan_from_welcome", "Scan"),
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
        app = self.app
        if not hasattr(app, "_recent_scans") or not app._recent_scans:
            return
        lv = self.query_one("#recent-list", ListView)
        lv.clear()
        for r in app._recent_scans[-10:]:
            lv.append(ListItem(Label(f"  {r}")))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        target = self.query_one("#target-input", Input).value.strip()
        if not target:
            self.notify("Please enter a target", severity="warning", timeout=3)
            return
        app = self.app
        app._scan_target = target
        app._scan_mode = event.button.id or "quick"
        app.start_scan()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.value.strip():
            app = self.app
            app._scan_target = event.value.strip()
            app._scan_mode = "quick"
            app.start_scan()


class ScanProgressScreen(Screen):
    BINDINGS = [
        Binding("q", "app.quit", "Quit"),
        Binding("h", "app.go_home", "Home"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            Static("[bold yellow]Scan in Progress[/bold yellow]", id="progress-title"),
            Static("", id="progress-target"),
            ProgressBar(total=100, show_eta=True, id="scan-progress"),
            Static("", id="progress-status"),
            RichLog(id="progress-log", highlight=True, markup=True, max_lines=200),
            id="progress-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        app = self.app
        target = getattr(app, "_scan_target", "unknown")
        mode = getattr(app, "_scan_mode", "quick")
        self.query_one("#progress-target", Static).update(f"  [cyan]{target}[/cyan]  [dim]({mode})[/dim]")

    def update_progress(self, pct: int, status: str) -> None:
        self.query_one("#scan-progress", ProgressBar).progress = pct
        self.query_one("#progress-status", Static).update(f"  [bold]{status}[/bold]")

    def append_log(self, msg: str) -> None:
        self.query_one("#progress-log", RichLog).write(msg)

    def reset(self) -> None:
        self.query_one("#scan-progress", ProgressBar).progress = 0
        self.query_one("#progress-status", Static).update("")
        self.query_one("#progress-log", RichLog).clear()


class ScanResultsScreen(Screen):
    BINDINGS = [
        Binding("q", "app.quit", "Quit"),
        Binding("h", "app.go_home", "Home"),
        Binding("n", "app.new_scan", "New Scan"),
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
        self._display_results()

    def _display_results(self) -> None:
        app = self.app
        findings = getattr(app, "_scan_findings", [])
        summary = getattr(app, "_scan_summary", "No results yet")
        self.query_one("#results-summary", Static).update(f"  [bold]{summary}[/bold]")
        rl = self.query_one("#results-findings", RichLog)
        rl.clear()
        if findings:
            for f in findings:
                sev = f.get("severity", "info")
                colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "blue", "info": "dim white"}
                style = colors.get(sev, "")
                rl.write(f"[{style}][{sev.upper()}][/{style}] {f.get('title', 'Untitled')}")
        else:
            rl.write("[dim]No findings to display[/dim]")


class AgentsScreen(Screen):
    BINDINGS = [
        Binding("q", "app.quit", "Quit"),
        Binding("h", "app.go_home", "Home"),
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


class ConfigScreen(Screen):
    BINDINGS = [
        Binding("q", "app.quit", "Quit"),
        Binding("h", "app.go_home", "Home"),
        Binding("s", "save_config", "Save"),
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
            Static("[dim]Key bindings: q=quit, h=home, s=save, n=scan[/dim]", id="config-hint"),
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

    def action_save_config(self) -> None:
        from bugfinder.core.config import settings
        api_key = self.query_one("#config-api-key", Input).value
        if api_key and api_key != "********":
            settings.nvidia_api_key = api_key
        reports_path = self.query_one("#config-reports-path", Input).value
        if reports_path:
            settings.reports_path = Path(reports_path)
        self.notify("Configuration saved", severity="information", timeout=2)


class BugFinderTUI(App):
    TITLE = "BugFinder"
    SUB_TITLE = f"v{__version__} - AI-Powered Bug Bounty Assistant"
    CSS_PATH = "app.tcss"

    BINDINGS = [
        Binding("1", "go_to('welcome')", "Home", priority=True),
        Binding("2", "go_to('progress')", "Progress", priority=True),
        Binding("3", "go_to('results')", "Results", priority=True),
        Binding("4", "go_to('agents')", "Agents", priority=True),
        Binding("5", "go_to('config')", "Config", priority=True),
        Binding("q", "quit", "Quit", priority=True),
        Binding("h", "go_to('welcome')", "Home", priority=True),
    ]

    _screen_instances: dict[str, Screen] = {}

    def on_mount(self) -> None:
        self._screen_instances = {
            "welcome": WelcomeScreen(),
            "progress": ScanProgressScreen(),
            "results": ScanResultsScreen(),
            "agents": AgentsScreen(),
            "config": ConfigScreen(),
        }
        for name, screen in self._screen_instances.items():
            self.install_screen(screen, name)
        self.push_screen("welcome")

    def action_go_to(self, name: str) -> None:
        if name in self._screen_instances:
            self.push_screen(name)

    def action_go_home(self) -> None:
        self.pop_screen()
        self.push_screen("welcome")

    def action_new_scan(self) -> None:
        self.pop_screen()
        self.push_screen("welcome")

    def start_scan(self) -> None:
        self._screen_instances["progress"].reset()
        self.push_screen("progress")
        self.run_scan_worker()

    def action_start_scan_from_welcome(self) -> None:
        welcome = self._screen_instances["welcome"]
        target = welcome.query_one("#target-input", Input).value.strip()
        if target:
            self._scan_target = target
            self._scan_mode = "quick"
            self.start_scan()
        else:
            welcome.notify("Please enter a target", severity="warning", timeout=3)

    @work(exclusive=True)
    async def run_scan_worker(self) -> None:
        target = self._scan_target
        mode = self._scan_mode
        progress = self._screen_instances["progress"]

        progress.append_log(f"[bold cyan]Starting {mode} scan on {target}[/bold cyan]")

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
                progress.update_progress(pct, step["rationale"])
                progress.append_log(f"[dim]→ {step['rationale']} ({step['agent']})[/dim]")

                agent = await _load_agent(step["agent"], context=ctx)
                try:
                    result = await agent.execute()
                    if result and result.findings:
                        for f in result.findings:
                            findings.append(f)
                            sev = f.get("severity", "info")
                            icon = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "ℹ"}.get(sev, "•")
                            progress.append_log(f"  {icon} [{sev.upper()}] {f['title']}")
                    if result and result.summary:
                        progress.append_log(f"  [green]✓ {result.summary}[/green]")
                    else:
                        progress.append_log(f"  [green]✓ {step['agent']} completed[/green]")
                except Exception as e:
                    progress.append_log(f"  [red]✗ {step['agent']} failed: {e}[/red]")

                elapsed = time.monotonic() - start_time
                progress.append_log(f"  [dim]⏱ {elapsed:.0f}s | {pct}%[/dim]")

            progress.update_progress(100, "Scan complete")
            progress.append_log("[bold green]✓ Scan completed successfully[/bold green]")

            self._scan_findings = findings
            self._scan_summary = f"{len(findings)} findings in {total} steps"
            if not hasattr(self, "_recent_scans"):
                self._recent_scans = []
            self._recent_scans.append(f"{target} ({mode}) - {len(findings)} findings")

            self._screen_instances["results"].refresh()
            self.pop_screen()
            self.push_screen("results")

        except Exception as e:
            progress.append_log(f"[bold red]✗ Scan failed: {e}[/bold red]")
            self._scan_summary = f"Scan failed: {e}"
