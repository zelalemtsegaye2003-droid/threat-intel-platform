from __future__ import annotations

import sys
import time
from fastapi import FastAPI, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from contextlib import asynccontextmanager

from app.config import get_settings
from app.logging_config import configure_logging, get_logger
from app.sentry_config import init_sentry
from app.metrics import (
    REQUEST_COUNT,
    REQUEST_LATENCY,
    REQUEST_IN_PROGRESS,
    ERROR_COUNT,
    EXCEPTION_COUNT,
    collect_default_metrics,
)
from app.api.v1.router import api_router
from app.db.postgres import init_db, init_security_db
from app.middleware import RateLimitMiddleware, SecurityHeadersMiddleware

logger = get_logger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    configure_logging()
    logger.info("application_starting", version="0.1.0", debug=settings.debug)

    # Initialize Sentry
    init_sentry(settings.sentry_dsn, settings.sentry_traces_sample_rate)

    await init_db()
    await init_security_db()
    logger.info("application_started", version="0.1.0", debug=settings.debug)
    yield
    logger.info("application_shutting_down")


def create_application() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="Threat Intelligence Platform",
        description="Modern threat intelligence platform with STIX 2.1, TAXII 2.x, and AI-powered analysis",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Security middleware (order matters - rate limit before CORS)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, calls=100, period=60)

    # Prometheus metrics middleware
    @app.middleware("http")
    async def prometheus_middleware(request: Request, call_next):
        """Record Prometheus metrics for each request."""
        method = request.method
        path = request.url.path

        REQUEST_IN_PROGRESS.labels(method=method, endpoint=path).inc()
        start_time = time.time()

        try:
            response: Response = await call_next(request)
            elapsed = time.time() - start_time

            REQUEST_COUNT.labels(method=method, endpoint=path, status_code=response.status_code).inc()
            REQUEST_LATENCY.labels(method=method, endpoint=path).observe(elapsed)

            if response.status_code >= 400:
                ERROR_COUNT.labels(method=method, endpoint=path, status_code=str(response.status_code)).inc()

            return response
        except Exception as e:
            elapsed = time.time() - start_time
            EXCEPTION_COUNT.labels(exception_type=type(e).__name__).inc()
            logger.error("request_failed", method=method, path=path, error=str(e), duration=elapsed)
            raise
        finally:
            REQUEST_IN_PROGRESS.labels(method=method, endpoint=path).dec()

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    app.include_router(api_router, prefix="/api/v1")

    # Auth endpoints
    from app.api.v1.endpoints import auth as auth_router
    app.include_router(auth_router.router, prefix="/api/v1/auth", tags=["Authentication"])

    # Prometheus /metrics endpoint
    @app.get("/metrics", tags=["Monitoring"], include_in_schema=False)
    async def metrics():
        """Prometheus metrics endpoint."""
        data, content_type = collect_default_metrics()
        return PlainTextResponse(content=data, media_type=content_type)

    # Root endpoint
    @app.get("/", tags=["Root"])
    async def root():
        return {
            "name": "Threat Intelligence Platform",
            "version": "0.1.0",
            "status": "operational",
            "docs": "/docs",
            "metrics": "/metrics",
            "endpoints": {
                "iocs": "/api/v1/iocs",
                "actors": "/api/v1/actors",
                "malware": "/api/v1/malware",
                "campaigns": "/api/v1/campaigns",
                "feeds": "/api/v1/feeds",
                "search": "/api/v1/search",
                "taxii": "/api/v1/taxii",
                "stix": "/api/v1/stix",
                "analysis": "/api/v1/analysis",
            },
        }

    # Health check
    @app.get("/health", tags=["Health"])
    async def health_check():
        return {"status": "healthy", "timestamp": "2026-04-27T16:00:00Z"}

    return app


app = create_application()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
    )