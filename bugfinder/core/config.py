from __future__ import annotations

from pathlib import Path

from platformdirs import user_config_dir, user_data_dir
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

APP_NAME = "bugfinder"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BF_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # AI Provider
    ai_provider: str = Field(default="nvidia", description="AI provider: nvidia, openai, anthropic, ollama")

    # NVIDIA
    nvidia_api_key: str = Field(default="", description="NVIDIA API key")
    nvidia_model: str = Field(default="minimax-m3", description="NVIDIA model name")
    nvidia_base_url: str = Field(
        default="https://integrate.api.nvidia.com/v1",
        description="NVIDIA API base URL",
    )

    # OpenAI
    openai_api_key: str = Field(default="", description="OpenAI API key")
    openai_model: str = Field(default="gpt-4o", description="OpenAI model name")
    openai_base_url: str = Field(default="https://api.openai.com/v1", description="OpenAI API base URL")

    # Anthropic
    anthropic_api_key: str = Field(default="", description="Anthropic API key")
    anthropic_model: str = Field(default="claude-3-opus-20240229", description="Anthropic model name")
    anthropic_base_url: str = Field(default="https://api.anthropic.com", description="Anthropic API base URL")

    # Ollama
    ollama_base_url: str = Field(default="http://localhost:11434", description="Ollama API base URL")
    ollama_model: str = Field(default="llama3", description="Ollama model name")

    ai_temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    ai_max_tokens: int = Field(default=4096)
    ai_enabled: bool = Field(default=True)

    # Database
    database_url: str = Field(
        default=(f"sqlite+aiosqlite:///{Path(user_data_dir(APP_NAME, ensure_exists=True)) / 'bf.db'}"),
        description="Database URL",
    )

    # Redis (for celery)
    redis_url: str = Field(default="", description="Redis URL for background tasks")

    # Scanning
    max_concurrent_tasks: int = Field(default=10)
    default_scan_profile: str = Field(default="quick")
    request_timeout: int = Field(default=30)
    rate_limit_per_second: int = Field(default=50)
    user_agent: str = Field(default="BugFinder/0.2.0 (Security Assessment Tool)")
    respect_robots: bool = Field(default=True)

    # Web UI
    web_host: str = Field(default="127.0.0.1")
    web_port: int = Field(default=8080)
    web_secret_key: str = Field(default="change-me-to-a-random-secret")
    web_session_expiry_hours: int = Field(default=24)

    # Directories
    reports_dir: str = Field(
        default=str(Path(user_data_dir(APP_NAME, ensure_exists=True)) / "reports"),
    )
    plugins_dir: str = Field(
        default=str(Path(user_config_dir(APP_NAME, ensure_exists=True)) / "plugins"),
    )
    cache_dir: str = Field(
        default=str(Path(user_data_dir(APP_NAME, ensure_exists=True)) / "cache"),
    )

    # Scope
    scope_enforcement: bool = Field(default=True)
    allowed_domains: list[str] = Field(default=[], description="Allowed domains for testing")

    # Notifications
    discord_webhook_url: str = Field(default="", description="Discord webhook URL")
    slack_webhook_url: str = Field(default="", description="Slack webhook URL")
    smtp_host: str = Field(default="", description="SMTP host")
    smtp_port: int = Field(default=587, description="SMTP port")
    smtp_user: str = Field(default="", description="SMTP username")
    smtp_password: str = Field(default="", description="SMTP password")
    email_from: str = Field(default="bugfinder@localhost", description="Email from address")
    email_to: str = Field(default="", description="Email to address")
    github_token: str = Field(default="", description="GitHub token for issue creation")
    github_repo: str = Field(default="", description="GitHub repo for issue creation")

    # General
    log_level: str = Field(default="INFO")
    debug: bool = Field(default=False)
    beginner_mode: bool = Field(default=True)
    educational_mode: bool = Field(default=True)

    @property
    def reports_path(self) -> Path:
        return Path(self.reports_dir)

    @property
    def plugins_path(self) -> Path:
        return Path(self.plugins_dir)

    @property
    def cache_path(self) -> Path:
        return Path(self.cache_dir)


settings = Settings()
