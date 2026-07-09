# Changelog

## [0.2.0] - 2026-07-09

### Added
- Web UI: FastAPI backend with HTMX + Alpine.js frontend (dashboard, scans, findings, projects)
- Web UI: Server-Sent Events for real-time scan progress streaming
- Web UI: Login/auth with API key and session tokens
- 22 new security agents: SSTI, XXE, GraphQL, JWT, CORS, CSP, cookies, CSRF, open redirect, host header, race condition, cache poisoning, Wayback Machine, GitHub dork, Google dorks, S3, GCP, Azure, Firebase, WebView, Android storage, Android deeplinks
- Bug Bounty Workflow Engine: 4-phase structured flow (Recon → Vuln Detection → Exploitation → Reporting)
- Exploit Engine: PoC generation (curl/Python/Burp) for all vulnerability types
- Notifications: Discord, Slack, Teams webhooks + SMTP email + GitHub issues
- CI/CD Mode: JUnit XML, SARIF output, exit-code based evaluation
- Multi-AI support: OpenAI, Anthropic, Ollama providers (configurable via BF_AI_PROVIDER)
- MCP Server for Cursor/Claude integration
- PDF report generation (via weasyprint)
- Scan-to-scan diff reports
- AI explainer for non-coder-friendly finding explanations
- AI false positive analysis
- AI finding correlation with attack chain detection
- AI payload selector per vulnerability type
- AI path discovery for hidden endpoints
- Parallel orchestrator for concurrent agent execution
- Pause/resume/cancel scan sessions
- Scheduled recurring scans (cron/interval via APScheduler)
- Batch scanning from YAML/text file targets
- Out-of-band callback server (interact.sh integration)
- docker-compose.yml with app + redis + postgres
- Dependabot configuration for automated dependency updates
- CONTRIBUTING.md with development guidelines

### Changed
- Updated to 40+ agents across 7 categories
- pyproject.toml: version 0.2.0, added web/notifications/celery extras
- Dockerfile: multi-stage build with uv, non-root user, HEALTHCHECK
- CLI: added `web`, `report`, improved `list-agents` commands
- Config: 40+ env vars across AI providers, web UI, notifications
- README: comprehensive rewrite with features, architecture, screenshots
- Package structure: new modules for web, workflow, exploit, notifications, ci

### Fixed
- Agent registry now discovers all 40+ agents
- Scheduler handles all agent types properly
- Database persistence for scans, findings, and assets
