from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class MCPTool:
    def __init__(self, name: str, description: str, handler: callable, parameters: dict[str, Any] | None = None):
        self.name = name
        self.description = description
        self.handler = handler
        self.parameters = parameters or {}


class MCPServer:
    def __init__(self):
        self.tools: dict[str, MCPTool] = {}
        self._register_default_tools()

    def _register_default_tools(self):
        self.register_tool(MCPTool(
            name="list_agents",
            description="List all available security assessment agents",
            handler=self._handle_list_agents,
            parameters={"type": "object", "properties": {}},
        ))
        self.register_tool(MCPTool(
            name="run_scan",
            description="Run a security scan against a target",
            handler=self._handle_run_scan,
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL, domain, IP, or APK path"},
                    "profile": {"type": "string", "enum": ["quick", "deep", "expert"], "default": "quick"},
                },
                "required": ["target"],
            },
        ))
        self.register_tool(MCPTool(
            name="get_findings",
            description="Get findings from a completed scan",
            handler=self._handle_get_findings,
            parameters={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "integer", "description": "Scan ID"},
                },
                "required": ["scan_id"],
            },
        ))
        self.register_tool(MCPTool(
            name="get_scan_status",
            description="Get the status of a scan",
            handler=self._handle_get_scan_status,
            parameters={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "integer", "description": "Scan ID"},
                },
                "required": ["scan_id"],
            },
        ))
        self.register_tool(MCPTool(
            name="list_projects",
            description="List all projects",
            handler=self._handle_list_projects,
            parameters={"type": "object", "properties": {}},
        ))

    def register_tool(self, tool: MCPTool):
        self.tools[tool.name] = tool

    async def handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action") or request.get("method", "")
        params = request.get("params", {}) or request.get("arguments", {})

        if action == "list_tools":
            return {
                "tools": [
                    {"name": t.name, "description": t.description, "parameters": t.parameters}
                    for t in self.tools.values()
                ]
            }

        tool = self.tools.get(action)
        if not tool:
            return {"error": f"Unknown tool: {action}"}

        try:
            result = await tool.handler(**params)
            return {"result": result}
        except Exception as e:
            logger.error("MCP handler error: %s", e)
            return {"error": str(e)}

    async def _handle_list_agents(self) -> list[dict[str, str]]:
        from bugfinder.core.registry import discover_agents
        agents = discover_agents()
        return [
            {"name": name, "class": cls.__name__}
            for name, cls in agents.items()
        ]

    async def _handle_run_scan(self, target: str, profile: str = "quick") -> dict[str, Any]:
        from bugfinder.core.types import TargetType
        from bugfinder.target.detector import detect_target_type
        from bugfinder.engine.scheduler import ScanOrchestrator
        from bugfinder.database.repository import Repository
        from bugfinder.database.session import async_session

        target_type = detect_target_type(target)

        async with async_session() as session:
            repo = Repository(session)
            scan = await repo.create_scan(target=target, target_type=target_type, profile=profile)
            scan_id = scan.id

        orchestrator = ScanOrchestrator()
        await orchestrator.run_scan(scan_id, target, target_type, profile)

        async with async_session() as session:
            repo = Repository(session)
            scan = await repo.get_scan(scan_id)
            findings = await repo.list_findings(scan_id=scan_id)

        return {
            "scan_id": scan_id,
            "target": target,
            "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
            "findings_count": len(findings),
        }

    async def _handle_get_findings(self, scan_id: int) -> list[dict[str, Any]]:
        from bugfinder.database.repository import Repository
        from bugfinder.database.session import async_session

        async with async_session() as session:
            repo = Repository(session)
            findings = await repo.list_findings(scan_id=scan_id)

        return [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "description": f.description,
                "category": f.category,
            }
            for f in findings
        ]

    async def _handle_get_scan_status(self, scan_id: int) -> dict[str, Any]:
        from bugfinder.database.repository import Repository
        from bugfinder.database.session import async_session

        async with async_session() as session:
            repo = Repository(session)
            scan = await repo.get_scan(scan_id)
            if not scan:
                return {"error": "Scan not found"}
            findings = await repo.list_findings(scan_id=scan_id)

        return {
            "scan_id": scan.id,
            "target": scan.target,
            "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
            "progress": scan.progress,
            "findings_count": len(findings),
        }

    async def _handle_list_projects(self) -> list[dict[str, Any]]:
        from bugfinder.database.repository import Repository
        from bugfinder.database.session import async_session

        async with async_session() as session:
            repo = Repository(session)
            projects = await repo.list_projects()

        return [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "created_at": p.created_at.isoformat() if hasattr(p.created_at, 'isoformat') else str(p.created_at),
            }
            for p in projects
        ]


mcp_server = MCPServer()
