.PHONY: install test lint format typecheck clean build docker dev

install:
	uv sync --all-extras

test:
	uv run python -m pytest tests/ -v --cov=bugfinder

lint:
	uv run ruff check bugfinder/ tests/

format:
	uv run ruff format bugfinder/ tests/

typecheck:
	uv run mypy bugfinder/ --ignore-missing-imports

clean:
	rm -rf .venv/ dist/ *.egg-info/ .pytest_cache/ __pycache__/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete

build:
	uv build

docker:
	docker build -t bugfinder:latest .

dev:
	uv run python -m bugfinder tui

precommit:
	uv run pre-commit run --all-files
