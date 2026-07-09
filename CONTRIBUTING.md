# Contributing to BugFinder

## Development Setup

```bash
git clone https://github.com/highoncomputers/BugFinder.git
cd BugFinder
make install
```

## Development Workflow

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes
3. Run quality checks:
   ```bash
   make lint       # Ruff lint
   make format     # Ruff format
   make typecheck  # Mypy
   make test       # Pytest with coverage
   ```
4. Run pre-commit hooks: `make precommit`
5. Commit and push

## Code Style

- Python 3.12+ with strict type hints
- Line length: 130 characters
- Ruff for linting and formatting
- Use `async/await` for I/O operations
- Use Pydantic models for data validation
- Use structlog for structured logging

## Adding a New Agent

1. Create the agent file in `bugfinder/agents/<category>/<name>.py`
2. Extend `BaseAgent` (see `bugfinder/agents/base.py`)
3. Implement the `execute()` method returning `AgentResult`
4. Register in the scheduler's agent map (`bugfinder/engine/scheduler.py`)
5. Add to the rule planner (`bugfinder/planner/rule_planner.py`)
6. Write tests in `tests/test_agents/`
7. Run all tests to verify

## Pull Request Process

1. Ensure all quality checks pass
2. Update documentation if needed
3. Add tests for new functionality
4. Update CHANGELOG.md
5. Submit PR with descriptive title and details

## Testing

```bash
make test        # Full test suite
make test-quick  # Skip slow tests
```

## Questions?

Open a GitHub Discussion or issue.
