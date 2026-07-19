from __future__ import annotations

from typing import Any

SYSTEM_CHAT = """You are BugFinder's AI Security Co-pilot — an expert security engineer assistant.
You help users understand vulnerabilities, interpret scan results, generate exploit PoCs, and learn security concepts.

Your capabilities:
- Answer questions about scan findings, vulnerabilities, and security concepts
- Generate exploit proof-of-concept code (curl, Python, requests)
- Summarize scan results and explain what they mean
- Suggest remediation steps for found vulnerabilities
- Recommend next steps for testing
- Explain security concepts in beginner-friendly terms
- Generate PoC commands that can be tested safely

Guidelines:
- Always prioritize safety and legality — never recommend attacking systems without authorization
- Explain technical concepts clearly — adapt to the user's knowledge level
- When generating exploit PoCs, clearly label them as proof-of-concept only
- Reference CWE, OWASP, and industry standards when relevant
- Be concise but thorough
- Prefer showing actual commands and code over theory

When asked about recent scans or findings, use the context provided to give specific, actionable answers.
When asked for exploit PoCs, provide working curl commands or Python scripts with clear documentation."""


class ChatAgent:
    def __init__(self, ai_client: Any | None = None):
        self.ai_client = ai_client
        self.conversation_history: list[dict[str, str]] = []

    async def chat(self, message: str, context: dict[str, Any] | None = None) -> str:
        if not self.ai_client:
            return "⚠ AI provider not configured. Go to **Settings** to add an API key."

        system_prompt = self._build_system_prompt(context)
        self.conversation_history.append({"role": "user", "content": message})

        messages = []
        messages.append({"role": "system", "content": system_prompt})

        for msg in self.conversation_history[-20:]:
            messages.append(msg)

        try:
            result = await self.ai_client.chat(messages, temperature=0.3, max_tokens=4096)
            reply = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            self.conversation_history.append({"role": "assistant", "content": reply})
            return reply
        except Exception as e:
            return f"⚠ AI error: {e}"

    def _build_system_prompt(self, context: dict[str, Any] | None) -> str:
        parts = [SYSTEM_CHAT]

        if not context:
            return "\n\n".join(parts)

        if context.get("findings"):
            findings = context["findings"]
            parts.append("## Current Scan Findings\n" + self._format_findings(findings))

        if context.get("scan"):
            scan = context["scan"]
            parts.append(
                f"## Current Scan\n"
                f"- Target: {scan.get('target', 'N/A')}\n"
                f"- Profile: {scan.get('profile', 'N/A')}\n"
                f"- Status: {scan.get('status', 'N/A')}\n"
                f"- Findings count: {scan.get('findings_count', 0)}\n"
            )

        if context.get("knowledge_graph"):
            kg = context["knowledge_graph"]
            parts.append(f"## Knowledge Graph\n- Nodes: {kg.get('node_count', 0)}\n- Edges: {kg.get('edge_count', 0)}\n")

        return "\n\n".join(parts)

    def _format_findings(self, findings: list[dict[str, Any]]) -> str:
        if not findings:
            return "No findings yet."
        lines = []
        for i, f in enumerate(findings[:25], 1):
            title = f.get("title", "Untitled")
            sev = f.get("severity", "info").upper()
            confidence = f.get("confidence", "medium")
            lines.append(f"{i}. [{sev}] {title} (confidence: {confidence})")
        if len(findings) > 25:
            lines.append(f"... and {len(findings) - 25} more findings")
        return "\n".join(lines)

    def clear_history(self) -> None:
        self.conversation_history.clear()
