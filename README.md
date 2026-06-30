# BugFinder

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/highoncomputers/BugFinder/actions/workflows/ci.yml/badge.svg)](https://github.com/highoncomputers/BugFinder/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](pyproject.toml)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker)](Dockerfile)
[![CodeQL](https://github.com/highoncomputers/BugFinder/actions/workflows/codeql.yml/badge.svg)](https://github.com/highoncomputers/BugFinder/actions/workflows/codeql.yml)
[![GitHub stars](https://img.shields.io/github/stars/highoncomputers/BugFinder?style=social)](https://github.com/highoncomputers/BugFinder)

AI-powered autonomous bug bounty assistant and security assessment platform.

BugFinder automatically determines the target type, selects appropriate assessment modules, executes safe scans, correlates findings, and generates professional reports — all while explaining each finding in plain language.

```bash
bf scan https://example.com
bf scan app.apk
bf scan 10.0.0.0/24
bf tui                           # Launch the terminal dashboard
```

---

## Quick Start

```bash
# Install
pip install bugfinder

# Set your NVIDIA API key (required for AI features)
export BF_NVIDIA_API_KEY="your-key-here"

# Run your first scan
bf scan https://example.com

# Launch the TUI dashboard
bf tui
```

---

## Features

- **Auto-detect**: Automatically identifies target type (website, API, APK, IP, Docker, etc.)
- **AI-Powered**: NVIDIA API integration for intelligent planning, explanation, and reporting
- **Zero Config**: Works out of the box — no manual configuration required for standard scans
- **Dual Mode**: Beginner mode (guided, educational) and Expert mode (full control)
- **Knowledge Graph**: Maintains relationships between discovered assets for smarter analysis
- **Plugin System**: Extensible via plugins for custom technologies and workflows
- **Rich TUI**: Terminal-based dashboard with real-time progress, findings explorer, and report preview
- **Multi-Format Reports**: Markdown, HTML, PDF, JSON, CSV export
- **Scope-Aware**: Built-in scope enforcement and rate limiting for safe testing

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        CLI (typer)                       │
│              bf scan | bf tui | bf report                │
└──────────┬──────────────────────────────────┬────────────┘
           │                                  │
           ▼                                  ▼
┌─────────────────────┐         ┌─────────────────────────┐
│   Target Detection   │         │   Textual TUI Dashboard │
│  (web / api / apk /  │         │  (live progress, find-  │
│   ip / cloud / ...)  │         │   ings, report preview) │
└──────────┬───────────┘         └─────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────┐
│                    Planner (AI + Rules)                   │
│     Selects agents, orders operations, sets scope        │
└──────────┬──────────────────────────────────┬────────────┘
           │                                  │
           ▼                                  ▼
┌─────────────────────┐         ┌─────────────────────────┐
│    Assessment Agents  │         │      Engine              │
│  ┌─────────────────┐ │         │  Scheduler + Executor    │
│  │ Web     │  API   │ │         │  (async task queue,      │
│  ├─────────────────┤ │         │   concurrency control,   │
│  │ Android │ Cloud │ │         │   rate limiting)         │
│  ├─────────────────┤ │         └──────────┬──────────────┘
│  │ Infra   │ Secrets││                    │
│  ├─────────────────┤ │                    │
│  │ Recon           │ │                    │
│  └─────────────────┘ │                    │
└───────────────────────┘                    │
           │                                  │
           └──────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────┐
│                   Knowledge Graph                        │
│         (asset relationships via NetworkX)               │
└──────────┬──────────────────────────────────┬────────────┘
           │                                  │
           ▼                                  ▼
┌─────────────────────┐         ┌─────────────────────────┐
│   Database           │         │   AI (NVIDIA API)       │
│  SQLAlchemy + Alembic│         │  Planning, explanations,│
│  (SQLite / Postgres) │         │  report generation      │
└───────────────────────┘         └─────────────────────────┘
           │                                  │
           └──────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────┐
│                    Reporting                              │
│   Markdown │ HTML │ PDF │ JSON │ CSV                     │
└─────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
bugfinder/
├── cli/                  # CLI commands + Textual TUI
├── core/                 # Config, types, exceptions
├── target/               # Target auto-detection
├── planner/              # AI + rule-based planner
├── agents/               # Assessment agents
│   ├── web/              # Web app scanners
│   ├── api/              # API testing
│   ├── android/          # APK analysis
│   ├── cloud/            # Cloud config review
│   ├── infra/            # Network/infrastructure
│   ├── secrets/          # Secret detection
│   └── recon/            # Reconnaissance
├── engine/               # Scheduler + executor
├── knowledge_graph/      # Asset relationship graph
├── database/             # SQLAlchemy models
├── ai/                   # NVIDIA API client
├── reporting/            # Report generators
├── plugins/              # Plugin system
├── security/             # Scope + rate limiting
└── learning/             # Educational resources
```

---

## CLI Reference

| Command | Description |
|---|---|
| `bf scan <target>` | Auto-detect and scan |
| `bf scan <target> --quick` | Lightweight scan |
| `bf scan <target> --deep` | Maximum coverage |
| `bf scan <target> --expert` | Full configuration control |
| `bf tui` | Launch Textual terminal UI |
| `bf report <scan_id>` | Generate report |
| `bf config <key> <value>` | Set configuration |
| `bf list-agents` | Show available agents |
| `bf plugin install <name>` | Install plugin |

---

## Configuration

Configuration via environment variables (prefixed with `BF_`), `.env` file, or `bf config`:

```bash
# Required for AI features
BF_NVIDIA_API_KEY=your_key_here
BF_NVIDIA_MODEL=minimax-m3

# Scope enforcement (comma-separated)
BF_ALLOWED_DOMAINS=example.com,api.example.com

# Scan settings
BF_MAX_CONCURRENT_TASKS=10
BF_RATE_LIMIT_PER_SECOND=50

# Mode
BF_BEGINNER_MODE=true
BF_EDUCATIONAL_MODE=true
```

---

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

# Run TUI
make dev
```

---

## FAQ

### What kind of targets can BugFinder scan?

BugFinder auto-detects websites (HTTP/HTTPS), REST/GraphQL APIs, Android APKs, IP ranges/subnets, Docker containers/images, and cloud provider configurations (AWS, GCP, Azure). It selects the appropriate assessment modules automatically.

### Does BugFinder require an internet connection?

Yes, for AI-powered features (planning, explanations, report generation) via the NVIDIA API. Offline scanning works but lacks intelligent analysis. Some agents (e.g., subdomain enumeration, OSINT) also require internet access.

### Is BugFinder safe to run against production targets?

BugFinder prioritizes safety with built-in scope enforcement, rate limiting, and read-only checks. However, always use `BF_ALLOWED_DOMAINS` and explicit scope configuration. The beginner mode adds confirmation prompts before each action.

### Can I run BugFinder in Docker?

Yes. See the [Dockerfile](Dockerfile). Build with `docker build -t bugfinder .` and run with `docker run bugfinder scan https://example.com`.

### What AI models does BugFinder support?

Currently NVIDIA API (NIM) with the `minimax-m3` model. Support for additional providers is planned.

### Can I use BugFinder without an AI API key?

Yes. Basic scanning, scope enforcement, and reporting work without AI. The AI enhances planning, explanation, and report generation.

### How do I add a new assessment agent?

See [CONTRIBUTING.md](CONTRIBUTING.md) for the agent development guide. Agents are Python classes that subclass `BaseAgent`.

### Does BugFinder store scan results?

Yes, in a local SQLite database by default (`bugfinder.db`). Configure `BF_DATABASE_URL` for Postgres in production deployments.

---

## Troubleshooting

### "No module named bugfinder"

Ensure you're in the virtual environment or have installed the package:
```bash
uv sync
# or
pip install -e .
```

### "NVIDIA API key not found"

Set the `BF_NVIDIA_API_KEY` environment variable or add it to a `.env` file in the working directory.

### Rate limiting errors

Increase `BF_RATE_LIMIT_PER_SECOND` if scanning a high-capacity target. Decrease it if your requests are being blocked.

### Tests fail with import errors

Run `make install` first to install all dependencies including development extras.

### Docker container exits immediately

Run the container with a command, e.g.:
```bash
docker run bugfinder scan https://example.com
```
The default entrypoint is `bf` with `--help`.

### "Database is locked" errors

BugFinder uses SQLite by default, which has limited concurrency. For concurrent scans, switch to Postgres via `BF_DATABASE_URL`.

### TUI is unresponsive

Ensure your terminal supports 24-bit color and is at least 80×24 characters. Try `export TERM=xterm-256color`.

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines, code style, and pull request process.

## Security

Report security vulnerabilities to security@bugfinder.dev. See [SECURITY.md](SECURITY.md) for our security policy and disclosure process.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## License

MIT — see [LICENSE](LICENSE) for details.
