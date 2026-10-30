from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.main import create_app

BACKEND_DIR = Path(__file__).resolve().parents[1]


def alembic_config(database_url: str) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.set_main_option("sqlalchemy.url", database_url)
    # Keep pytest's log capture intact instead of letting alembic.ini reconfigure logging.
    config.attributes["configure_logger"] = False
    return config


@pytest.fixture
def database_url(tmp_path: Path) -> str:
    """A fresh, empty SQLite file per test (no migrations applied)."""
    return f"sqlite:///{(tmp_path / 'aegis-test.db').as_posix()}"


@pytest.fixture
def migrated_database_url(database_url: str) -> str:
    """A fresh database upgraded with the real Alembic migrations."""
    command.upgrade(alembic_config(database_url), "head")
    return database_url


def make_settings(database_url: str) -> Settings:
    return Settings(
        environment="test",
        database_url=database_url,
        cors_origins=["http://localhost:5173"],
    )


@pytest.fixture
def app(migrated_database_url: str) -> FastAPI:
    return create_app(make_settings(migrated_database_url))


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db_session(app: FastAPI) -> Iterator[Session]:
    with app.state.session_factory() as session:
        yield session
