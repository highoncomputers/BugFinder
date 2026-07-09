# BugFinder

[![CI](https://github.com/highoncomputers/BugFinder/actions/workflows/ci.yml/badge.svg)](https://github.com/highoncomputers/BugFinder/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.2.0-orange)](https://github.com/highoncomputers/BugFinder/releases)

**AI-powered autonomous bug bounty assistant and security assessment platform.**

BugFinder automatically determines the target type, selects appropriate assessment modules, executes safe scans, correlates findings, and generates professional reports — all while explaining each finding in plain language for non-experts.

```bash
bf scan https://example.com       # CLI scan
bf scan app.apk --deep            # Deep APK analysis
bf tui                            # Terminal dashboard
bf web                            # Launch Web UI
```

## Features

- **Auto-Detect Target**: Automatically identifies target type (website, API, APK, IP, Docker, CIDR, cloud)
- **AI-Powered**: Multi-provider AI (NVIDIA, OpenAI, Anthropic, Ollama) for planning, explanation, and reporting
- **40+ Security Agents**: Recon (DNS, tech, subdomain, wayback, GitHub, Google dorks), Web (XSS, SQLi, SSRF, LFI, SSTI, XXE, GraphQL, JWT, CORS, CSP, CSRF, cookies, redirect, host header, race), API (discover, fuzz, rate), Cloud (S3, GCP, Azure, Firebase), Android (decompile, WebView, storage, deep links), Infra (port, service, TLS), Secrets detection
- **Web UI**: FastAPI + HTMX + Alpine.js — reactive dashboard, live scan streaming, project management
- **Bug Bounty Workflow**: 4-phase structured flow (Recon → Vuln Detection → Exploitation → Reporting) with progress tracking
- **Knowledge Graph**: NetworkX-based relationship mapping between assets, findings, and attack chains
- **Exploit Engine**: PoC generation (curl, Python, Burp) for every finding type
- **Notifications**: Discord, Slack, Teams webhooks + email + GitHub issues
- **CI/CD Mode**: JUnit XML, SARIF output, exit-code based results
- **Plugin System**: Extensible via plugins for custom technologies and workflows
- **Multi-Format Reports**: Markdown, HTML, JSON, PDF
- **Scope-Aware**: Built-in scope enforcement and rate limiting for safe testing
- **Docker Support**: Containerized deployment with docker-compose (app + redis + postgres)
- **MCP Server**: Integration with Cursor, Claude, and other MCP-compatible tools

## Quick Start

```bash
# Install from source
git clone https://github.com/highoncomputers/BugFinder.git
cd BugFinder
make install

# Set your AI API key
export BF_NVIDIA_API_KEY="your-key-here"

# Run your first scan
bf scan https://example.com

# Launch the Web UI
bf web

# Launch the TUI dashboard
bf tui
```

### Docker

```bash
docker build -t bugfinder:latest .
docker run -e BF_NVIDIA_API_KEY=your-key bugfinder:latest scan https://example.com

# Full stack with docker-compose
docker compose up -d
# Web UI at http://localhost:8080
```

## CLI Reference

| Command | Description |
|---|---|
| `bf scan <target>` | Auto-detect and scan |
| `bf scan <target> --quick` | Lightweight scan |
| `bf scan <target> --deep` | Maximum coverage |
| `bf scan <target> --expert` | Full configuration control |
| `bf tui` | Launch Textual terminal UI |
| `bf web` | Launch Web UI (FastAPI) |
| `bf report <scan_id>` | Generate report from DB |
| `bf list-agents` | Show all 40+ agents |
| `bf config <key> <value>` | Set configuration |
| `bf plugin install <name>` | Install plugin |

## Web UI

BugFinder now includes a full web interface:

- **Dashboard** — Overview stats, recent scans, start new scan
- **Scans** — List/view/stop scans with live SSE streaming
- **Findings** — Filter by severity/status/category, update state
- **Projects** — Organize scans into projects
- **Reports** — Download markdown/HTML/JSON reports
- **API** — Full REST API for integrations

Start with: `bf web` (defaults to http://127.0.0.1:8080)

## Configuration

Via environment variables (prefixed with `BF_`), `.env` file, or `bf config`:

```bash
# AI Provider (nvidia, openai, anthropic, ollama)
BF_AI_PROVIDER=nvidia
BF_NVIDIA_API_KEY=your_key_here

# Web UI
BF_WEB_HOST=127.0.0.1
BF_WEB_PORT=8080
BF_WEB_SECRET_KEY=your-random-secret

# Scope enforcement (comma-separated)
BF_ALLOWED_DOMAINS=example.com,api.example.com

# Scan settings
BF_MAX_CONCURRENT_TASKS=10
BF_RATE_LIMIT_PER_SECOND=50

# Mode
BF_BEGINNER_MODE=true
BF_EDUCATIONAL_MODE=true
```

## Architecture

```
bugfinder/
├── cli/                  # CLI commands + Textual TUI
├── core/                 # Config, types, exceptions, registry
├── target/               # Target auto-detection
├── planner/              # AI + rule-based planner
├── agents/               # 40+ assessment agents
│   ├── web/              # Web app scanners (15 agents)
│   ├── api/              # API testing (4 agents)
│   ├── android/          # APK analysis (4 agents)
│   ├── cloud/            # Cloud config (5 agents)
│   ├── infra/            # Network/infrastructure (3 agents)
│   ├── recon/            # Reconnaissance (6 agents)
│   ├── secrets/          # Secret detection
│   └── verification/     # Finding verification
├── engine/               # Scheduler + parallel + batch + PoC + OOB
├── workflow/             # Bug bounty workflow engine
├── exploit/              # Exploit strategies + executor
├── web/                  # FastAPI web UI
├── knowledge_graph/      # Asset relationship graph
├── database/             # SQLAlchemy models + migrations
├── ai/                   # Multi-provider AI client
├── reporting/            # Report generators (md/html/json/pdf/diff)
├── notifications/        # Webhooks + email + GitHub issues
├── plugins/              # Plugin system
├── security/             # Scope + rate limiting
├── learning/             # Educational resources
└── ci/                   # CI/CD mode (JUnit, SARIF)
```

## Development

```bash
# Clone and setup
git clone https://github.com/highoncomputers/BugFinder.git
cd BugFinder
make install

# Run tests
make test

# Lint and format
make lint
make format

# Type check
make typecheck

# Run Web UI (hot reload)
make dev-web

# Run TUI
make dev
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT
