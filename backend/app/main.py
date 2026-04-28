from __future__ import annotations

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import get_settings
from app.api.v1.router import api_router
from app.db.postgres import init_db, init_security_db
from app.middleware import RateLimitMiddleware, SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    settings = get_settings()
    await init_db()
    await init_security_db()  # Create users and audit_logs tables
    print(f"Starting Threat Intelligence Platform v0.1.0")
    print(f"Debug mode: {settings.debug}")
    yield
    # Shutdown
    print("Shutting down...")


def create_application() -> FastAPI:
    """Create and configure FastAPI application."""
    settings = get_settings()

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

    # Root endpoint
    @app.get("/", tags=["Root"])
    async def root():
        return {
            "name": "Threat Intelligence Platform",
            "version": "0.1.0",
            "status": "operational",
            "docs": "/docs",
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
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
    )
