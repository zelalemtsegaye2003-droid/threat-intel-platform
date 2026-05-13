from __future__ import annotations

import structlog

logger = structlog.get_logger(__name__)


def init_sentry(dsn: str | None, traces_sample_rate: float = 1.0) -> None:
    """Initialize Sentry SDK if DSN is configured."""
    if not dsn:
        logger.info("sentry_skipped", reason="No SENTRY_DSN configured")
        return

    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration

        sentry_sdk.init(
            dsn=dsn,
            traces_sample_rate=traces_sample_rate,
            integrations=[
                FastApiIntegration(),
                LoggingIntegration(
                    level=structlog.stdlib.WARNING,
                    event_level=structlog.stdlib.ERROR,
                ),
            ],
        )
        logger.info("sentry_initialized", sample_rate=traces_sample_rate)
    except ImportError:
        logger.warning("sentry_import_failed", reason="sentry-sdk not installed")