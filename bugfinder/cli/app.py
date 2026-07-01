from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, ListView, Static


class WelcomeScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Static("[bold yellow]BugFinder[/bold yellow]", id="title"),
            Static("AI-Powered Bug Bounty Assistant", id="subtitle"),
            Static("", id="spacer"),
            Input(placeholder="Enter target (URL, APK, IP, domain...)", id="target-input"),
            Horizontal(
                Button("Quick Scan", variant="primary", id="quick"),
                Button("Deep Scan", variant="default", id="deep"),
                Button("Expert Mode", variant="warning", id="expert"),
            ),
            Static("", id="recent-label"),
            Static("[bold]Recent Projects[/bold]", id="recent-header"),
            ListView(id="recent-list"),
            id="main-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#target-input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        target = self.query_one("#target-input", Input).value.strip()
        if not target:
            self.notify("Please enter a target", severity="warning")
            return
        self.app.action_scan(target, event.button.id or "quick")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        target = event.value.strip()
        if target:
            self.app.action_scan(target, "quick")


class BugFinderTUI(App):
    TITLE = "BugFinder"
    SUB_TITLE = "AI-Powered Bug Bounty Assistant"
    CSS = """
    Screen {
        align: center middle;
    }
    #main-container {
        width: 80%;
        height: 100%;
        align: center top;
        padding: 2;
    }
    #title {
        text-style: bold;
        text-align: center;
        color: yellow;
        margin-bottom: 0;
    }
    #subtitle {
        text-align: center;
        color: gray;
        margin-bottom: 2;
    }
    #target-input {
        margin: 1 0;
        width: 100%;
    }
    Horizontal {
        align: center middle;
        margin: 1 0;
    }
    Button {
        margin: 0 1;
    }
    #recent-header {
        margin-top: 2;
        text-style: bold;
    }
    #recent-list {
        height: 8;
        border: solid gray;
    }
    """

    def compose(self) -> ComposeResult:
        yield WelcomeScreen()

    def action_scan(self, target: str, mode: str) -> None:
        self.notify(f"Starting {mode} scan on {target}", severity="information")
