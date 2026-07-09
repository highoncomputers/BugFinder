from __future__ import annotations

import pytest

from bugfinder.core.types import Severity, Confidence


@pytest.mark.asyncio
async def test_ssti_agent_imports():
    from bugfinder.agents.web.ssti import SSTIAgent
    agent = SSTIAgent()
    assert agent.name == "ssti"
    assert agent.category == "web"


@pytest.mark.asyncio
async def test_graphql_agent_imports():
    from bugfinder.agents.web.graphql import GraphQLAgent
    agent = GraphQLAgent()
    assert agent.name == "graphql"


@pytest.mark.asyncio
async def test_jwt_agent_imports():
    from bugfinder.agents.web.jwt import JWTAgent
    agent = JWTAgent()
    assert agent.name == "jwt"


@pytest.mark.asyncio
async def test_cors_agent_imports():
    from bugfinder.agents.web.cors import CORSAgent
    agent = CORSAgent()
    assert agent.name == "cors"


@pytest.mark.asyncio
async def test_csp_agent_imports():
    from bugfinder.agents.web.csp import CSPAgent
    agent = CSPAgent()
    assert agent.name == "csp"


@pytest.mark.asyncio
async def test_wayback_agent_imports():
    from bugfinder.agents.recon.wayback import WaybackAgent
    agent = WaybackAgent()
    assert agent.name == "wayback"


@pytest.mark.asyncio
async def test_s3_agent_imports():
    from bugfinder.agents.cloud.s3 import S3Agent
    agent = S3Agent()
    assert agent.name == "s3"


@pytest.mark.asyncio
async def test_firebase_agent_imports():
    from bugfinder.agents.cloud.firebase import FirebaseAgent
    agent = FirebaseAgent()
    assert agent.name == "firebase"


@pytest.mark.asyncio
async def test_webview_agent_imports():
    from bugfinder.agents.android.webview import AndroidWebViewAgent
    agent = AndroidWebViewAgent()
    assert agent.name == "webview"


@pytest.mark.asyncio
async def test_workflow_engine_imports():
    from bugfinder.workflow.engine import WorkflowEngine
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
    from bugfinder.engine.poc_generator import PoCGenerator, PoC
    poc = PoCGenerator._xss_poc("https://example.com", "Test XSS")
    assert poc.vulnerability == "Cross-Site Scripting (XSS)"
    assert "alert" in poc.curl_command


@pytest.mark.asyncio
async def test_scheduler_agent_map():
    from bugfinder.engine.scheduler import ScanOrchestrator
    orch = ScanOrchestrator()
    agent = await orch._load_agent("web.xss")
    assert agent is not None
    assert agent.name == "xss" or hasattr(agent, 'name')


@pytest.mark.asyncio
async def test_ai_client_multi_provider():
    from bugfinder.ai.client import get_ai_client, NVIDIAProvider
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
    from bugfinder.workflow.reporter import PhaseReporter
    from bugfinder.workflow import Phase
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
    from bugfinder.reporting.diff import diff_findings, FindingDiff
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
    from bugfinder.engine.pause_resume import ScanManager, ScanControlState
    mgr = ScanManager()
    ctrl = mgr.register_scan("test-1")
    assert ctrl.state == ScanControlState.RUNNING
    ctrl.pause()
    assert ctrl.state == ScanControlState.PAUSED
    ctrl.resume()
    assert ctrl.state == ScanControlState.RUNNING
    ctrl.cancel()
    assert ctrl.state == ScanControlState.CANCELLED
