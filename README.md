# BugFinder

AI-powered autonomous bug bounty assistant and security assessment platform.

BugFinder automatically determines the target type, selects appropriate assessment modules, executes safe scans, correlates findings, and generates professional reports — all while explaining each finding in plain language.

```bash
bf scan https://example.com
bf scan app.apk
bf scan 10.0.0.0/24
bf tui                           # Launch the terminal dashboard
```

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

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Run `make precommit` before committing
4. Open a Pull Request

## License

MIT
