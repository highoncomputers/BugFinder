.PHONY: install test lint format typecheck clean build docker dev docker-up docker-down migrate web worker beat precommit

# ── Setup ──────────────────────────────────────────────────────────────────

install:
	uv sync --all-extras

install-prod:
	uv sync --all-extras --no-dev

# ── Testing ────────────────────────────────────────────────────────────────

test:
	uv run python -m pytest tests/ -v --cov=bugfinder --cov-report=term

test-quick:
	uv run python -m pytest tests/ -v -m "not slow"

test-file:
	uv run python -m pytest $(file) -v

# ── Linting & Formatting ──────────────────────────────────────────────────

lint:
	uv run ruff check bugfinder/ tests/

lint-fix:
	uv run ruff check --fix bugfinder/ tests/

format:
	uv run ruff format bugfinder/ tests/

format-check:
	uv run ruff format --check bugfinder/ tests/

typecheck:
	uv run mypy bugfinder/ --ignore-missing-imports

# ── Cleanup ────────────────────────────────────────────────────────────────

clean:
	rm -rf .venv/ dist/ *.egg-info/ .pytest_cache/ __pycache__/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete

# ── Build ──────────────────────────────────────────────────────────────────

build:
	uv build

docker:
	docker build -t bugfinder:latest .

docker-no-cache:
	docker build --no-cache -t bugfinder:latest .

# ── Docker Compose ────────────────────────────────────────────────────────

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

# ── Development ────────────────────────────────────────────────────────────

dev:
	uv run python -m bugfinder tui

dev-web:
	uv run uvicorn bugfinder.web.app:create_app --host 127.0.0.1 --port 8080 --reload

dev-worker:
	uv run celery -A bugfinder.worker worker --loglevel=info

dev-beat:
	uv run celery -A bugfinder.worker beat --loglevel=info

# ── Database ───────────────────────────────────────────────────────────────

migrate:
	uv run alembic upgrade head

migrate-fresh:
	uv run alembic downgrade base && uv run alembic upgrade head

migrate-autogenerate:
	uv run alembic autogenerate -m "$(message)"

# ── Pre-commit ─────────────────────────────────────────────────────────────

precommit:
	uv run pre-commit run --all-files

precommit-install:
	uv run pre-commit install

# ── Help ───────────────────────────────────────────────────────────────────

help:
	@echo "BugFinder Development Commands"
	@echo "=============================="
	@echo "install              Install all dependencies"
	@echo "test                 Run all tests with coverage"
	@echo "test-quick           Run quick tests (skip slow)"
	@echo "lint                 Run ruff lint check"
	@echo "lint-fix             Auto-fix lint issues"
	@echo "format               Format code with ruff"
	@echo "typecheck            Run mypy type checking"
	@echo "clean                Remove build artifacts"
	@echo "build                Build Python package"
	@echo "docker               Build Docker image"
	@echo "docker-up            Start all services (docker compose)"
	@echo "docker-down          Stop all services"
	@echo "dev                  Run TUI (textual)"
	@echo "dev-web              Run web UI (hot reload)"
	@echo "migrate              Run database migrations"
	@echo "precommit            Run pre-commit hooks"
