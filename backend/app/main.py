"""FastAPI application factory: middleware and routers."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.routes import router as v1_router
from app.config import get_settings
from app.core.inference import InferenceEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("app")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.api_version,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    # CORS for the React frontend
    app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://ml-project-sbgj.onrender.com",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

    app.include_router(v1_router, prefix="/api/v1")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        loaded = InferenceEngine.instance().load()
        if not loaded:
            logger.warning("Model bundle missing at startup; /predict will return 503 until trained.")
        if get_settings().history_enabled:
            from app.db.database import run_migrations

            version = run_migrations()
            logger.info("Database schema migrations applied (version=%s).", version)
        yield

    app.router.lifespan_context = lifespan

    @app.get("/", include_in_schema=False)
    def root():
        return {"service": settings.app_name, "docs": "/docs", "api": "/api/v1"}

    return app


app = create_app()
