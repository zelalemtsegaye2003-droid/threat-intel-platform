from __future__ import annotations

from pathlib import Path
from functools import lru_cache
from typing import Any

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

    # Ollama LLM
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    # Security
    secret_key: str = "your-secret-key-change-in-production-min-32-chars"
    jwt_secret: str = "your_jwt_secret_key_here_min_32_chars"
    jwt_algorithm: str = "HS256"
    jwt_expires_minutes: int = 30
    encryption_key: str = "your_fernet_key_here"

    # External APIs (optional)
    alienvault_otx_api_key: str | None = None
    virustotal_api_key: str | None = None
    shodan_api_key: str | None = None

    # Application
    debug: bool = True
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: list[str] = ["http://localhost:3000"]

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
