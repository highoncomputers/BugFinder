from __future__ import annotations

import pytest

from bugfinder.agents.base import AgentContext


@pytest.fixture
def mock_context():
    return AgentContext(
        target="https://example.com",
        target_type="website",
        scan_id="1",
        knowledge_graph=None,
        ai_client=None,
        repository=None,
    )


@pytest.mark.asyncio
async def test_ssti_agent_imports(mock_context):
    from bugfinder.agents.web.ssti import SSTIAgent

    agent = SSTIAgent(context=mock_context)
    assert agent.name == "ssti"
    assert agent.category == "web"


@pytest.mark.asyncio
async def test_graphql_agent_imports(mock_context):
    from bugfinder.agents.web.graphql import GraphQLAgent

    agent = GraphQLAgent(context=mock_context)
    assert agent.name == "graphql"


@pytest.mark.asyncio
async def test_jwt_agent_imports(mock_context):
    from bugfinder.agents.web.jwt import JWTAgent

    agent = JWTAgent(context=mock_context)
    assert agent.name == "jwt"


@pytest.mark.asyncio
async def test_cors_agent_imports(mock_context):
    from bugfinder.agents.web.cors import CORSAgent

    agent = CORSAgent(context=mock_context)
    assert agent.name == "cors"


@pytest.mark.asyncio
async def test_csp_agent_imports(mock_context):
    from bugfinder.agents.web.csp import CSPAgent

    agent = CSPAgent(context=mock_context)
    assert agent.name == "csp"


@pytest.mark.asyncio
async def test_wayback_agent_imports(mock_context):
    from bugfinder.agents.recon.wayback import WaybackAgent

    agent = WaybackAgent(context=mock_context)
    assert agent.name == "wayback"


@pytest.mark.asyncio
async def test_s3_agent_imports(mock_context):
    from bugfinder.agents.cloud.s3 import S3Agent

    agent = S3Agent(context=mock_context)
    assert agent.name == "s3"


@pytest.mark.asyncio
async def test_firebase_agent_imports(mock_context):
    from bugfinder.agents.cloud.firebase import FirebaseAgent

    agent = FirebaseAgent(context=mock_context)
    assert agent.name == "firebase"


@pytest.mark.asyncio
async def test_webview_agent_imports(mock_context):
    from bugfinder.agents.android.webview import AndroidWebViewAgent

    agent = AndroidWebViewAgent(context=mock_context)
    assert agent.name == "webview"


@pytest.mark.asyncio
async def test_workflow_engine_imports():
    from bugfinder.workflow import Phase, PhaseStatus

    assert len(Phase) == 4
    assert len(PhaseStatus) == 5


@pytest.mark.asyncio
async def test_exploit_engine_imports():
    from bugfinder.exploit.engine import ExploitEngine

    engine = ExploitEngine()
    assert engine is not None


@pytest.mark.asyncio
async def test_notifications_imports():
    from bugfinder.notifications.webhooks import send_discord_webhook, send_slack_webhook

    assert callable(send_discord_webhook)
    assert callable(send_slack_webhook)


@pytest.mark.asyncio
async def test_ci_mode_imports():
    from bugfinder.ci.mode import CIMode

    ci = CIMode()
    assert ci is not None


@pytest.mark.asyncio
async def test_mcp_server_imports():
    from bugfinder.mcp_server import MCPServer

    server = MCPServer()
    assert len(server.tools) >= 5


@pytest.mark.asyncio
async def test_parallel_orchestrator_imports():
    from bugfinder.engine.parallel import ParallelOrchestrator

    po = ParallelOrchestrator(max_concurrent=5)
    assert po.max_concurrent == 5


@pytest.mark.asyncio
async def test_poc_generator_imports():
    from bugfinder.engine.poc_generator import PoCGenerator

    poc = PoCGenerator._xss_poc("https://example.com", "Test XSS")
    assert poc.vulnerability == "Cross-Site Scripting (XSS)"
    assert "alert" in poc.curl_command


@pytest.mark.asyncio
async def test_scheduler_agent_map():
    from bugfinder.engine.scheduler import ScanOrchestrator

    orch = ScanOrchestrator()
    agent = await orch._load_agent("web.xss")
    assert agent is not None
    assert agent.name == "xss" or hasattr(agent, "name")


@pytest.mark.asyncio
async def test_ai_client_multi_provider():
    from bugfinder.ai.client import NVIDIAProvider, get_ai_client

    client = get_ai_client()
    # Should return NVIDIAProvider or None depending on config
    assert client is None or isinstance(client, NVIDIAProvider)


@pytest.mark.asyncio
async def test_false_positive_analyzer_imports():
    from bugfinder.ai.false_positive import FalsePositiveAnalyzer

    fp = FalsePositiveAnalyzer()
    assert fp is not None


@pytest.mark.asyncio
async def test_finding_correlator_imports():
    from bugfinder.ai.correlator import FindingCorrelator

    fc = FindingCorrelator()
    assert fc is not None


@pytest.mark.asyncio
async def test_phase_reporter_imports():
    from bugfinder.workflow import Phase
    from bugfinder.workflow.reporter import PhaseReporter

    summary = PhaseReporter.phase_summary(Phase.RECON, [])
    assert summary["phase"] == "recon"
    assert summary["total_findings"] == 0


@pytest.mark.asyncio
async def test_payload_selector_imports():
    from bugfinder.ai.payload_selector import PayloadSelector

    ps = PayloadSelector()
    payloads = ps._default_payloads("xss")
    assert len(payloads) > 0
    assert payloads[0]["value"] == "<script>alert(1)</script>"


@pytest.mark.asyncio
async def test_finding_diff():
    from bugfinder.reporting.diff import diff_findings

    prev = [{"title": "test1", "severity": "high", "status": "open"}]
    curr = [{"title": "test1", "severity": "high", "status": "fixed"}]
    diff = diff_findings(prev, curr)
    assert len(diff.fixed_findings) > 0


@pytest.mark.asyncio
async def test_batch_scanner_imports():
    from bugfinder.engine.batch import BatchScanner, BatchTarget

    bs = BatchScanner()
    assert bs.max_concurrent > 0
    bt = BatchTarget(target="https://example.com")
    assert bt.target == "https://example.com"


@pytest.mark.asyncio
async def test_scan_control():
    from bugfinder.engine.pause_resume import ScanControlState, ScanManager

    mgr = ScanManager()
    ctrl = mgr.register_scan("test-1")
    assert ctrl.state == ScanControlState.RUNNING
    ctrl.pause()
    assert ctrl.state == ScanControlState.PAUSED
    ctrl.resume()
    assert ctrl.state == ScanControlState.RUNNING
    ctrl.cancel()
    assert ctrl.state == ScanControlState.CANCELLED


@pytest.mark.asyncio
async def test_c2_implant_agent(mock_context):
    from bugfinder.agents.redteam.c2_implant import C2ImplantAgent

    agent = C2ImplantAgent(context=mock_context)
    result = await agent.execute()
    assert agent.name == "redteam.c2_implant"
    assert len(result.findings) > 0
    assert any("c2" in f["id"] for f in result.findings)


@pytest.mark.asyncio
async def test_priv_esc_agent(mock_context):
    from bugfinder.agents.redteam.priv_esc import PrivEscAgent

    mock_context.target = "https://linux-server.example.com"
    agent = PrivEscAgent(context=mock_context)
    result = await agent.execute()
    assert agent.name == "redteam.priv_esc"
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_lateral_movement_agent(mock_context):
    from bugfinder.agents.redteam.lateral_movement import LateralMovementAgent

    agent = LateralMovementAgent(context=mock_context)
    result = await agent.execute()
    assert agent.name == "redteam.lateral_movement"
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_persistence_agent(mock_context):
    from bugfinder.agents.redteam.persistence import PersistenceAgent

    mock_context.target = "linux-server"
    agent = PersistenceAgent(context=mock_context)
    result = await agent.execute()
    assert agent.name == "redteam.persistence"
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_evasion_agent(mock_context):
    from bugfinder.agents.redteam.evasion import EvasionAgent

    agent = EvasionAgent(context=mock_context)
    result = await agent.execute()
    assert agent.name == "redteam.evasion"
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_data_exfil_agent(mock_context):
    from bugfinder.agents.redteam.data_exfil import DataExfilAgent

    agent = DataExfilAgent(context=mock_context)
    result = await agent.execute()
    assert agent.name == "redteam.data_exfil"
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_pivot_scan_agent(mock_context):
    from bugfinder.agents.redteam.pivot import PivotScanAgent

    agent = PivotScanAgent(context=mock_context)
    result = await agent.execute()
    assert agent.name == "redteam.pivot_scan"
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_redteam_agents_in_scheduler(mock_context):
    from bugfinder.engine.scheduler import ScanOrchestrator

    orch = ScanOrchestrator()
    c2 = await orch._load_agent("redteam.c2_implant", context=mock_context)
    assert c2 is not None
    assert c2.name == "redteam.c2_implant"

    priv = await orch._load_agent("redteam.priv_esc", context=mock_context)
    assert priv is not None
    assert priv.name == "redteam.priv_esc"

    lat = await orch._load_agent("redteam.lateral_movement", context=mock_context)
    assert lat is not None
    assert lat.name == "redteam.lateral_movement"

    pers = await orch._load_agent("redteam.persistence", context=mock_context)
    assert pers is not None
    assert pers.name == "redteam.persistence"

    ev = await orch._load_agent("redteam.evasion", context=mock_context)
    assert ev is not None
    assert ev.name == "redteam.evasion"

    exfil = await orch._load_agent("redteam.data_exfil", context=mock_context)
    assert exfil is not None
    assert exfil.name == "redteam.data_exfil"

    pivot = await orch._load_agent("redteam.pivot_scan", context=mock_context)
    assert pivot is not None
    assert pivot.name == "redteam.pivot_scan"
