from __future__ import annotations

"""
Prompt templates for AI interactions.

Each prompt is a function that takes context and returns a (system, user) tuple.
"""


SYSTEM_PLANNER = """You are BugFinder's AI security assessment planner.
Your role is to analyze the target, review current findings, and decide the next best step.
Only recommend steps that are legal and within scope.
Be concise and specific. Output JSON with: {{"next_step": "...", "rationale": "...", "agents": ["..."]}}"""

SYSTEM_EXPLAINER = """You are BugFinder's AI security mentor.
You explain security findings in clear, simple language.
Include what the finding is, why it matters, how it could be exploited, and how to fix it.
Be educational and encouraging."""

SYSTEM_REPORT = """You are BugFinder's AI report writer.
Generate professional security assessment reports.
Include executive summary, technical findings, evidence references, and remediation guidance.
Be clear, factual, and actionable."""

SYSTEM_CORRELATOR = """You are BugFinder's AI finding correlator.
Analyze findings and evidence to identify relationships, attack chains, and duplicates.
Output JSON with correlations between finding IDs."""


def planner_prompt(target_type: str, target: str, graph_summary: str) -> tuple[str, str]:
    system = SYSTEM_PLANNER
    user = f"""Target Type: {target_type}
Target: {target}
Current Knowledge Graph: {graph_summary}

What should I test next? Respond in JSON format."""
    return system, user


def explainer_prompt(finding_title: str, description: str, evidence: str) -> tuple[str, str]:
    system = SYSTEM_EXPLAINER
    user = f"""Finding: {finding_title}
Description: {description}
Evidence: {evidence}

Explain this finding in simple terms. Include:
1. What is this vulnerability?
2. Why does it matter?
3. How could a real attacker use it?
4. How can developers fix it?
5. Where can I learn more?"""
    return system, user


def report_prompt(
    target: str, findings_summary: str, graph_summary: str
) -> tuple[str, str]:
    system = SYSTEM_REPORT
    user = f"""Target: {target}
Findings: {findings_summary}
Asset Graph: {graph_summary}

Generate a professional security assessment report."""
    return system, user
