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

    # AI
    nvidia_api_key: str = Field(default="", description="NVIDIA API key")
    nvidia_model: str = Field(default="minimax-m3", description="NVIDIA model name")
    nvidia_base_url: str = Field(
        default="https://integrate.api.nvidia.com/v1",
        description="NVIDIA API base URL",
    )
    ai_temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    ai_max_tokens: int = Field(default=4096)
    ai_enabled: bool = Field(default=True)

    # Database
    database_url: str = Field(
        default=(
            f"sqlite+aiosqlite:///{Path(user_data_dir(APP_NAME, ensure_exists=True)) / 'bf.db'}"
        ),
        description="Database URL",
    )

    # Scanning
    max_concurrent_tasks: int = Field(default=10)
    default_scan_profile: str = Field(default="quick")
    request_timeout: int = Field(default=30)
    rate_limit_per_second: int = Field(default=50)
    user_agent: str = Field(default="BugFinder/0.1.0 (Security Assessment Tool)")
    respect_robots: bool = Field(default=True)

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
