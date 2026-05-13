from __future__ import annotations

from functools import lru_cache

from pydantic import Field, AliasChoices, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    # Database
    database_url: str = "postgresql://admin:secure_password@localhost:5432/threatintel"

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "secure_password"

    # Qdrant
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333

    # Redis
    redis_url: str = "redis://localhost:6379"

    # RabbitMQ
    rabbitmq_url: str = "amqp://admin:secure_password@localhost:5672"

    # Gemini AI (replaces Ollama)
    gemini_api_key: str | None = Field(
        default=None,
        description="Google API key for Gemini (or use GOOGLE_API_KEY env var).",
    )
    gemini_model: str = Field(
        default="gemini-2.5-flash",
        description="Gemini model to use (e.g., gemini-2.5-flash, gemini-2.5-pro).",
    )
    google_cloud_project: str | None = Field(
        default=None,
        description="Google Cloud project ID (for ADC authentication).",
    )
    google_cloud_location: str = Field(
        default="global",
        description="Google Cloud location (e.g., global, us-central1).",
    )
    use_vertex_ai: bool = Field(
        default=False,
        description="Set to True to use Vertex AI (Agent Platform) instead of express mode.",
    )

    # Security
    # SECRET_KEY kept for backwards compatibility, but JWT uses JWT_SECRET consistently.
    secret_key: str = Field(
        default="your-secret-key-change-in-production-min-32-chars",
        validation_alias=AliasChoices("SECRET_KEY"),
    )
    jwt_secret: str = Field(
        default="your_jwt_secret_key_here_min_32_chars",
        validation_alias=AliasChoices("JWT_SECRET", "JWT_SIGNING_KEY"),
        description="JWT signing key (min 32 chars in production).",
    )
    jwt_algorithm: str = "HS256"
    jwt_expires_minutes: int = 30
    encryption_key: str = "your_fernet_key_here"

    # External APIs (optional)
    alienvault_otx_api_key: str | None = None
    virustotal_api_key: str | None = None
    shodan_api_key: str | None = None

    # Application
    environment: str = Field(
        default="development",
        description='Set to "production" for stricter defaults (docs off unless overridden).',
    )
    debug: bool = True
    log_level: str = Field(
        default="info",
        description="Logging level (debug, info, warning, error).",
    )
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3001",
        ]
    )
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] | None = None
    cors_allow_headers: list[str] | None = None
    enable_api_docs: bool | None = Field(
        default=None,
        description="If unset: disabled in production, enabled otherwise.",
    )
    # Database schema lifecycle
    db_schema_management: str = Field(
        default="migrations",
        description='Use "migrations" (recommended) or "autocreate" (dev only).',
    )
    rate_limit_backend: str = Field(
        default="redis",
        description='Use "redis" (multi-replica safe) or "memory" (single process only).',
    )
    rate_limit_calls: int = 100
    rate_limit_period_seconds: int = 60
    rate_limit_key_prefix: str = "ratelimit:api"
    security_hsts_max_age_seconds: int | None = Field(
        default=None,
        description='If set (>0), sends Strict-Transport-Security (use only behind HTTPS).',
    )
    tls_terminated_upstream: bool = Field(
        default=False,
        description="Set true when TLS is enforced at an ingress/reverse proxy before this app.",
    )
    security_csp: str | None = Field(
        default=None,
        description="Overrides default Content-Security-Policy.",
    )
    uvicorn_workers: int = Field(
        default=1,
        ge=1,
        le=33,
        description="Uvicorn worker processes (>1 disables --reload semantics).",
    )
    uvicorn_timeout_keep_alive: int = Field(
        default=65,
        ge=5,
        le=86400,
        description="seconds for keep-alive; raise behind slow proxies/load balancers.",
    )
    run_db_migrations_on_start: bool = Field(
        default=False,
        description="If True, Docker entrypoint runs Alembic upgrade before Uvicorn starts.",
    )
    readiness_require_redis: bool | None = Field(
        default=None,
        description="If unset: Redis is checked on /ready only when rate_limit_backend=redis.",
    )
    enable_metrics: bool = Field(
        default=False,
        description="Expose Prometheus metrics at /metrics (recommended behind auth).",
    )
    metrics_require_auth: bool | None = Field(
        default=None,
        description="If unset: required in production, not required otherwise.",
    )

    @field_validator("metrics_require_auth", mode="before")
    @classmethod
    def parse_metrics_auth(cls, v: Any) -> bool | None:
        """Handle empty string as None."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    # Observability
    sentry_dsn: str | None = None
    sentry_traces_sample_rate: float = Field(
        default=1.0,
        description="Sentry traces sample rate (0.0 to 1.0).",
    )
    otlp_export_endpoint: str | None = Field(
        default=None,
        description="OTLP export endpoint for distributed tracing (e.g. http://jaeger:4318).",
    )

    # Proxy / client IP trust
    trust_x_forwarded_for: bool = Field(
        default=False,
        description="Trust X-Forwarded-For only when requests come from trusted_proxy_ips.",
    )
    # Temporarily comment out problematic field
    # trusted_proxy_ips: list[str] = Field(
    #     default_factory=lambda: ["127.0.0.1"],
    #     description="IP allowlist for reverse proxies allowed to set X-Forwarded-For.",
    # )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


def reload_settings() -> Settings:
    """Reload settings from environment."""
    get_settings.cache_clear()
    return get_settings()
