# Contributing to BugFinder

Thank you for your interest in contributing to BugFinder! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating, you agree to maintain a respectful and inclusive environment. Harassment, trolling, and discrimination are not tolerated.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/BugFinder.git`
3. Set up the development environment:

```bash
cd BugFinder
make install
```

## Development Workflow

```bash
# Run tests
make test

# Lint code
make lint

# Format code
make format

# Type check
make typecheck

# Run pre-commit hooks
make precommit
```

### Pre-commit

We use pre-commit hooks to enforce code quality. Install and run:

```bash
uv run pre-commit install
make precommit
```

## Pull Request Guidelines

1. Create a feature branch: `git checkout -b feature/description`
2. Make your changes with clear, descriptive commits
3. Run `make precommit` and `make test` before pushing
4. Open a PR against the `main` branch
5. Ensure CI passes on your PR

### PR requirements

- All tests must pass
- New features must include tests
- Type annotations must be present for all new code
- Lint and format checks must pass
- Documentation must be updated if behaviour changes

## Code Style

- **Line length**: 120 characters
- **Formatting**: Ruff (replaces Black + isort)
- **Type hints**: Required for all public APIs; strict mypy mode
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_CASE` for constants

## Testing

- Write tests using pytest with `asyncio_mode = "auto"`
- Place tests in `tests/` mirroring the `bugfinder/` package structure
- Mock external services (AI APIs, network requests)
- Aim for at least 80% coverage on new code

## Security Considerations

Since BugFinder is a security tool:

- Never hardcode credentials or API keys
- Always validate and sanitize inputs from targets
- Do not introduce code that could cause harm to targets
- Use `pathvalidate` for file path sanitization when writing reports
- Respect scope enforcement and rate limiting in all contributed modules
- Document security-relevant behaviour in your PR description

## Documentation

- Use docstrings for all public modules, classes, and functions (Google style)
- Update relevant CLI help text if commands change
- Add or update README sections for user-facing changes

## Adding Agents

To add a new assessment agent:

1. Create a module under `bugfinder/agents/<category>/`
2. Subclass `BaseAgent` from `bugfinder.agents.base`
3. Register the agent in `bugfinder/agents/__init__.py`
4. Add tests in `tests/agents/`
5. Include educational content in `bugfinder/learning/`

## Questions

Open a discussion on GitHub or ask in the project's community channels.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
