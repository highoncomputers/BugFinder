# Changelog

All notable changes to BugFinder will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-01

### Added

- Initial release of BugFinder
- **CLI**: `bf scan`, `bf tui`, `bf report`, `bf config`, `bf list-agents`, `bf plugin` commands
- **Auto-detection**: Automatic target type identification (website, API, APK, IP range, Docker, cloud)
- **AI integration**: NVIDIA API for intelligent planning, explanation, and report generation
- **Dual mode**: Beginner (guided + educational) and Expert (full control) modes
- **Knowledge graph**: Asset relationship mapping using NetworkX
- **Plugin system**: Extensible architecture for custom modules
- **Textual TUI**: Rich terminal dashboard with real-time scan progress
- **Multi-format reports**: Markdown, HTML, PDF, JSON, CSV export
- **Scope enforcement**: Domain/IP allowlisting and rate limiting
- **Assessment agents**:
  - Web application scanners
  - API testing
  - APK analysis
  - Cloud configuration review
  - Infrastructure/network scanning
  - Secret detection
  - Reconnaissance
- **Database**: SQLAlchemy + Alembic with SQLite and Postgres support
- **Docker support**: Pre-built container images
