from __future__ import annotations

import pytest


def test_commands_module_imports():
    from bugfinder.cli.commands import _format_duration, _show_banner, app, console

    assert app.info.name == "bf"
    assert console is not None
    assert callable(_show_banner)
    assert callable(_format_duration)


def test_format_duration():
    from bugfinder.cli.commands import _format_duration

    assert _format_duration(30) == "30s"
    assert _format_duration(90) == "1m 30s"
    assert _format_duration(3661) == "1h 1m 1s"


def test_commands_exist():
    from bugfinder.cli.commands import app

    cmd_names = [c.callback.__name__ for c in app.registered_commands if c.callback]
    assert "scan" in cmd_names
    assert "wizard" in cmd_names
    assert "redteam" in cmd_names
    assert "tui" in cmd_names
    assert "web" in cmd_names
    assert "report" in cmd_names
    assert "config" in cmd_names
    assert "examples" in cmd_names
    assert "list_agents" in cmd_names
    assert "plugin" in cmd_names


@pytest.mark.asyncio
async def test_wizard_module_imports():
    from bugfinder.cli.wizard import (
        REDTEAM_OPS,
        SCAN_PROFILES,
        _show_header,
        _show_menu,
        run_wizard,
    )

    assert "1" in REDTEAM_OPS
    assert "1" in SCAN_PROFILES
    assert callable(_show_header)
    assert callable(_show_menu)
    assert callable(run_wizard)


@pytest.mark.asyncio
async def test_wizard_redteam_ops():
    from bugfinder.cli.wizard import REDTEAM_OPS

    assert len(REDTEAM_OPS) == 7
    assert REDTEAM_OPS["1"][1] == "c2"
    assert REDTEAM_OPS["2"][1] == "priv-esc"
    assert REDTEAM_OPS["3"][1] == "lateral"
    assert REDTEAM_OPS["4"][1] == "persistence"
    assert REDTEAM_OPS["5"][1] == "evasion"
    assert REDTEAM_OPS["6"][1] == "exfil"
    assert REDTEAM_OPS["7"][1] == "pivot"


def test_wizard_scan_profiles():
    from bugfinder.cli.wizard import SCAN_PROFILES

    assert len(SCAN_PROFILES) == 4
    assert SCAN_PROFILES["1"][1] == "quick"
    assert SCAN_PROFILES["2"][1] == "deep"
    assert SCAN_PROFILES["3"][1] == "expert"
    assert SCAN_PROFILES["4"][1] == "auto"


def test_tui_app_imports():
    from bugfinder.cli.app import (
        AgentsScreen,
        BugFinderTUI,
        ConfigScreen,
        ScanProgressScreen,
        ScanResultsScreen,
        WelcomeScreen,
    )

    assert issubclass(WelcomeScreen, object)
    assert issubclass(ScanProgressScreen, object)
    assert issubclass(ScanResultsScreen, object)
    assert issubclass(AgentsScreen, object)
    assert issubclass(ConfigScreen, object)
    assert BugFinderTUI.TITLE == "BugFinder"


def test_tui_scenes_registered():
    from bugfinder.cli.app import BugFinderTUI

    app = BugFinderTUI()
    assert "welcome" in app.SCREENS
    assert "progress" in app.SCREENS
    assert "results" in app.SCREENS
    assert "agents" in app.SCREENS
    assert "config" in app.SCREENS


def test_tui_bindings():
    from bugfinder.cli.app import BugFinderTUI

    app = BugFinderTUI()
    binding_keys = {b.key for b in app.BINDINGS}
    assert "q" in binding_keys
    assert "h" in binding_keys
    assert "s" in binding_keys
    assert "r" in binding_keys
    assert "a" in binding_keys
    assert "c" in binding_keys
    assert "1" in binding_keys
    assert "2" in binding_keys
    assert "3" in binding_keys
    assert "4" in binding_keys
    assert "5" in binding_keys


def test_tui_actions():
    from bugfinder.cli.app import BugFinderTUI

    app = BugFinderTUI()
    assert hasattr(app, "action_go_home")
    assert hasattr(app, "action_start_scan")
    assert hasattr(app, "action_show_results")
    assert hasattr(app, "action_show_agents")
    assert hasattr(app, "action_show_config")
    assert hasattr(app, "action_screen_welcome")
    assert hasattr(app, "action_screen_progress")
    assert hasattr(app, "action_screen_results")
    assert hasattr(app, "action_screen_agents")
    assert hasattr(app, "action_screen_config")


def test_tui_css_path():
    from bugfinder.cli.app import BugFinderTUI

    app = BugFinderTUI()
    assert app.CSS_PATH is not None


@pytest.mark.asyncio
async def test_load_agent_function():
    from bugfinder.agents.base import AgentContext
    from bugfinder.cli.commands import _load_agent

    ctx = AgentContext(
        target="https://example.com",
        target_type="website",
        scan_id="1",
        knowledge_graph=None,
        ai_client=None,
        repository=None,
    )

    agent = await _load_agent("web.xss", context=ctx)
    assert agent is not None
    assert agent.name == "web.xss"

    stub = await _load_agent("nonexistent.agent", context=ctx)
    assert stub is not None
    assert "Stub" in type(stub).__name__


def test_app_tcss_exists():
    from pathlib import Path
    tcss_path = Path(__file__).parent.parent / "bugfinder" / "cli" / "app.tcss"
    assert tcss_path.exists(), f"app.tcss not found at {tcss_path}"
    content = tcss_path.read_text()
    assert len(content) > 100
    assert "Screen" in content
    assert "Footer" in content
