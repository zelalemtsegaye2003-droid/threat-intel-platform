"""Optional OpenTelemetry tracing setup — degrades gracefully if dependencies are missing."""
from __future__ import annotations

import structlog

logger = structlog.get_logger(__name__)


def setup_tracing() -> None:
    """Configure OpenTelemetry tracing with FastAPI and Celery instrumentation.
    Gracefully skips if dependencies are not installed."""
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            ConsoleSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.semconv.resource import ResourceAttributes
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.celery import CeleryInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.instrumentation.logging import LoggingInstrumentor

        from app.config import get_settings

        settings = get_settings()

        # Try OTLP exporter
        otlp_exporter = None
        otlp_endpoint = settings.otlp_export_endpoint
        if otlp_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                    OTLPSpanExporter,
                )
                otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
                logger.info("otlp_exporter_configured", endpoint=otlp_endpoint)
            except Exception as e:
                logger.warning("otlp_exporter_failed", error=str(e))

        # Resource identifies this service in traces
        resource = Resource.create(
            {
                ResourceAttributes.SERVICE_NAME: "threat-intel-platform",
                ResourceAttributes.SERVICE_VERSION: "0.1.0",
                "deployment.environment": settings.environment,
            }
        )

        # Configure tracer provider
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

        if otlp_exporter:
            provider.add_span_processor(BatchSpanProcessor(otlp_exporter))

        # Set global tracer provider
        trace.set_tracer_provider(provider)

        # Instrument FastAPI
        FastAPIInstrumentor().instrument()

        # Instrument Celery
        CeleryInstrumentor().instrument()

        # Instrument httpx
        HTTPXClientInstrumentor().instrument()

        # Instrument Python logging
        LoggingInstrumentor().instrument(set_logging_context=True)

        logger.info("tracing_setup_complete", exporter="console+otlp" if otlp_exporter else "console")

    except ImportError as e:
        logger.warning("tracing_skipped", reason=f"Missing dependency: {e}")


def get_tracer(__name__: str):
    """Get a tracer for the given module name. Returns None if tracing is unavailable."""
    try:
        from opentelemetry import trace
        return trace.get_tracer(__name__)
    except ImportError:
        return None