"""FastAPI application factory.

Run locally with::

    uvicorn app.main:create_app --factory --reload

Using a factory (instead of a module-level ``app``) means importing this module
has no side effects, so tests can build apps with their own settings.
"""

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.routes import (
    alerts,
    dashboard,
    detection,
    evaluation,
    events,
    health,
    incidents,
    ingestion,
    scenarios,
)
from app.core.config import Settings, get_settings
from app.core.errors import register_error_handlers
from app.db.session import build_engine, build_session_factory

API_PREFIX = "/api/v1"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level)

    engine = build_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(
        title="AEGIS Security Platform API",
        description="Detect. Investigate. Defend. — security event analysis and "
        "detection engineering API. Not hardened for public internet exposure; "
        "see SECURITY.md.",
        version=__version__,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    register_error_handlers(app)

    api = APIRouter(prefix=API_PREFIX)
    api.include_router(health.router)
    api.include_router(events.router)
    api.include_router(ingestion.router)
    api.include_router(detection.router)
    api.include_router(alerts.router)
    api.include_router(incidents.router)
    api.include_router(dashboard.router)
    api.include_router(scenarios.router)
    api.include_router(evaluation.router)
    app.include_router(api)

    return app
