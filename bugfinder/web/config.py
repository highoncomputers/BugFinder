from pydantic_settings import BaseSettings


class WebSettings(BaseSettings):
    web_host: str = "127.0.0.1"
    web_port: int = 8080
    web_secret_key: str = "change-me-to-a-random-secret"
    web_session_expiry_hours: int = 24
    web_allowed_origins: str = "http://localhost:8080"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.web_allowed_origins.split(",") if o.strip()]

    model_config = {"env_prefix": "BF_"}
