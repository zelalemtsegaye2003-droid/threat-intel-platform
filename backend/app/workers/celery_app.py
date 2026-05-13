from __future__ import annotations

import structlog
from celery import Celery
from celery.schedules import crontab
from celery.signals import task_prerun, task_postrun, task_failure

from app.config import get_settings
from app.metrics import TASK_COUNT, TASK_DURATION

logger = structlog.get_logger(__name__)
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
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)

# Celery task metrics
@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, **kwargs):
    task.start_time = task.time()

@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, retval=None, state=None, **kwargs):
    duration = task.time() - getattr(task, "start_time", task.time())
    TASK_DURATION.labels(task_name=task.name).observe(duration)
    TASK_COUNT.labels(task_name=task.name, status=state).inc()
    logger.info("celery_task_completed", task=task.name, state=state, duration=duration)

@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, **kwargs):
    logger.error("celery_task_failed", task=sender.name, error=str(exception), task_id=task_id)

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
