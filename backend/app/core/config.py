"""Application settings.

All configuration comes from environment variables prefixed with ``AEGIS_``
(optionally loaded from a ``.env`` file). Nothing secret is hardcoded here;
see ``.env.example`` at the repository root for the documented variables.
"""

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
DEFAULT_SQLITE_PATH = BACKEND_DIR / "data" / "aegis.db"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"

    # CORS is an explicit allow-list. In local development the Vite dev server
    # proxies /api, so the browser never needs CORS; this list only matters
    # when the frontend is served from a different origin.
    # NoDecode lets us accept a plain comma-separated string instead of JSON.
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173"]

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Ingestion limits. They bound memory use per request and keep a single
    # oversized or hostile upload from stalling the (single-process) API.
    max_ingest_bytes: int = Field(default=5 * 1024 * 1024, gt=0)
    max_ingest_records: int = Field(default=10_000, gt=0)
    max_record_bytes: int = Field(default=64 * 1024, gt=0)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("cors_origins")
    @classmethod
    def _reject_wildcard(cls, value: list[str]) -> list[str]:
        # A wildcard origin would let any website call the API from a
        # visitor's browser. Refuse it rather than silently allowing it.
        if "*" in value:
            raise ValueError("Wildcard CORS origin is not allowed; list origins explicitly.")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
