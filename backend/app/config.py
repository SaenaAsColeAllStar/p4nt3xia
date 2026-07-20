from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="P4NT3XIA_",
        env_file=".env",
        extra="ignore",
    )

    app_name: str = "P4NT3XIA"
    api_prefix: str = "/api"
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://frontend:3000",
    ]
    # Database — SQLite by default; set DATABASE_URL for Postgres
    database_url: str = ""
    # Auth (Phase 4) — off by default for personal single-user use
    auth_enabled: bool = False
    jwt_secret: str = "change-me-p4nt3xia-dev-secret"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24 * 7  # 7 days
    bootstrap_admin_user: str = ""
    bootstrap_admin_password: str = ""
    bootstrap_admin_email: str | None = None
    # Tool binaries — override via env if installed elsewhere
    subfinder_path: str = "subfinder"
    nmap_path: str = "nmap"
    ffuf_path: str = "ffuf"
    whatweb_path: str = "whatweb"
    nuclei_path: str = "nuclei"
    katana_path: str = "katana"
    sqlmap_path: str = "sqlmap"
    dalfox_path: str = "dalfox"
    hydra_path: str = "hydra"
    ssrfmap_path: str = "ssrfmap"
    jwt_tool_path: str = "jwt_tool"
    frida_path: str = "frida"
    # Default wordlist for ffuf (small/medium for Deep Scan)
    ffuf_wordlist: str = str(
        Path(__file__).resolve().parent.parent / "tools" / "wordlists" / "common.txt"
    )
    hydra_wordlist: str = str(
        Path(__file__).resolve().parent.parent / "tools" / "wordlists" / "passwords.txt"
    )
    # Timeouts (seconds)
    default_timeout: int = 120
    tool_timeout: int = 300

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v: object) -> object:
        if isinstance(v, str):
            import json

            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [s.strip() for s in v.split(",") if s.strip()]
        return v


settings = Settings()
