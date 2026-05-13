from __future__ import annotations

import structlog
from prometheus_client import Counter, Histogram, Gauge

logger = structlog.get_logger(__name__)

# === Request Metrics ===
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
)

REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

REQUEST_IN_PROGRESS = Gauge(
    "http_requests_in_progress",
    "HTTP requests currently in progress",
    ["method", "endpoint"],
)

# === Error Metrics ===
ERROR_COUNT = Counter(
    "http_errors_total",
    "Total HTTP errors (4xx, 5xx)",
    ["method", "endpoint", "status_code"],
)

EXCEPTION_COUNT = Counter(
    "exceptions_total",
    "Total unhandled exceptions",
    ["exception_type"],
)

# === Database Metrics ===
DB_POOL_CONNECTIONS = Gauge(
    "db_pool_connections",
    "Number of active DB pool connections",
    ["database"],
)

DB_POOL_WAITING = Gauge(
    "db_pool_waiting",
    "Number of requests waiting for a DB connection",
    ["database"],
)

# === Cache Metrics ===
CACHE_REQUESTS = Counter(
    "cache_requests_total",
    "Total cache requests",
    ["type", "hit_miss"],
)

CACHE_SIZE = Gauge(
    "cache_keys_total",
    "Number of keys in cache",
    ["cache"],
)

# === Feed Metrics ===
FEED_INGESTION_COUNT = Counter(
    "feed_ingestions_total",
    "Total feed ingestion attempts",
    ["feed", "status"],
)

FEED_INGESTION_DURATION = Histogram(
    "feed_ingestion_duration_seconds",
    "Feed ingestion duration in seconds",
    ["feed"],
)

# === Celery Task Metrics ===
TASK_COUNT = Counter(
    "celery_tasks_total",
    "Total Celery tasks executed",
    ["task_name", "status"],
)

TASK_DURATION = Histogram(
    "celery_task_duration_seconds",
    "Celery task duration in seconds",
    ["task_name"],
)

# === LLM Metrics ===
LLM_REQUEST_COUNT = Counter(
    "llm_requests_total",
    "Total LLM API requests",
    ["model", "operation"],
)

LLM_LATENCY = Histogram(
    "llm_request_duration_seconds",
    "LLM API request latency",
    ["model", "operation"],
)

LLM_ERROR_COUNT = Counter(
    "llm_errors_total",
    "Total LLM errors",
    ["model", "error_type"],
)

# === IOC Metrics ===
IOC_COUNT = Gauge(
    "iocs_total",
    "Total IOCs in the system",
    ["type"],
)

IOC_BY_THREAT_LEVEL = Gauge(
    "iocs_by_threat_level",
    "IOCs grouped by threat level",
    ["threat_level"],
)


def get_metrics_registry():
    """Get the default Prometheus registry."""
    from prometheus_client import REGISTRY

    return REGISTRY


def collect_default_metrics():
    """Collect default process and platform metrics."""
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

    return generate_latest(), CONTENT_TYPE_LATEST