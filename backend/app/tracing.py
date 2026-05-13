from __future__ import annotations

import structlog

logger = structlog.get_logger(__name__)


def setup_tracing() -> None:
    """Configure OpenTelemetry tracing with FastAPI and Celery instrumentation."""
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
    )
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.semconv.resource import ResourceAttributes
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.celery import CeleryInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.instrumentation.logging import LoggingInstrumentor

    from app.config import get_settings

    settings = get_settings()

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

    # Console exporter for local development
    provider.add_span_processor(
        BatchSpanProcessor(ConsoleSpanExporter(out=structlog.stdlib.stdlib.BoundLogger))
    )

    # OTLP exporter (for Jaeger, Zipkin, or Grafana Tempo)
    otlp_endpoint = settings.otlp_export_endpoint
    if otlp_endpoint:
        try:
            otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
            provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
            logger.info("otlp_exporter_configured", endpoint=otlp_endpoint)
        except Exception as e:
            logger.warning("otlp_exporter_failed", error=str(e))

    # Set global tracer provider
    trace.set_tracer_provider(provider)

    # Instrument FastAPI
    FastAPIInstrumentor().instrument()

    # Instrument Celery
    CeleryInstrumentor().instrument()

    # Instrument httpx (outgoing HTTP calls to VirusTotal, Shodan, etc.)
    HTTPXClientInstrumentor().instrument()

    # Instrument Python logging to create spans from log records
    LoggingInstrumentor().instrument(set_logging_context=True)

    logger.info("tracing_setup_complete", exporter="console+otlp" if otlp_endpoint else "console")


def get_tracer(__name__: str):
    """Get a tracer for the given module name."""
    from opentelemetry import trace

    return trace.get_tracer(__name__)