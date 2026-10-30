"""Read-only view of the effective configuration (no secrets exist to expose)."""

from pathlib import PurePath

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy.engine import make_url

from app import __version__
from app.core.config import Settings
from app.core.limits import DEFAULT_MAX_BODY_BYTES
from app.detection.mitre import ATTACK_VERSION
from app.detection.registry import RULES

router = APIRouter(tags=["settings"])


class SettingsOut(BaseModel):
    version: str
    environment: str
    database: str
    cors_origins: list[str]
    auto_detect: bool
    log_level: str
    max_ingest_bytes: int
    max_ingest_records: int
    max_record_bytes: int
    max_request_body_bytes: int
    attack_version: str
    rule_count: int
    authentication: str


@router.get("/settings", response_model=SettingsOut, summary="Effective configuration")
def effective_settings(request: Request) -> SettingsOut:
    """Values come from AEGIS_* environment variables (see .env.example) and are
    read-only here. Only the database backend and file name are shown, not the
    full path."""
    settings: Settings = request.app.state.settings
    url = make_url(settings.database_url)
    database = url.get_backend_name()
    if url.database:
        database += f" ({PurePath(url.database).name})"
    return SettingsOut(
        version=__version__,
        environment=settings.environment,
        database=database,
        cors_origins=settings.cors_origins,
        auto_detect=settings.auto_detect,
        log_level=settings.log_level,
        max_ingest_bytes=settings.max_ingest_bytes,
        max_ingest_records=settings.max_ingest_records,
        max_record_bytes=settings.max_record_bytes,
        max_request_body_bytes=DEFAULT_MAX_BODY_BYTES,
        attack_version=ATTACK_VERSION,
        rule_count=len(RULES),
        authentication="none: run on localhost only (see SECURITY.md)",
    )
