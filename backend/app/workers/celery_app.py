from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.config import get_settings

settings = get_settings()

# Initialize Celery with RabbitMQ broker
celery_app = Celery(
    "threat_intel_platform",
    broker=settings.rabbitmq_url,
    backend=settings.redis_url,
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)

# Periodic tasks
celery_app.conf.beat_schedule = {
    "ingest-feeds-every-hour": {
        "task": "app.workers.celery_app.ingest_feeds_task",
        "schedule": crontab(minute=0),  # Every hour
    },
    "update-graph-metrics-every-30-min": {
        "task": "app.workers.celery_app.update_graph_metrics",
        "schedule": crontab(minute="*/30"),
    },
}
