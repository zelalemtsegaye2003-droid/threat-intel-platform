"""Manage database migrations with Alembic.

Usage:
    python -m scripts.manage_db upgrade     # Run all pending migrations
    python -m scripts.manage_db upgrade head
    python -m scripts.manage_db history
    python -m scripts.manage_db current
    python -m scripts.manage_db downgrade -1
"""
from __future__ import annotations

import sys
from alembic import command
from alembic.config import Config

from app.config import get_settings

settings = get_settings()


def get_alembic_config() -> Config:
    """Get Alembic configuration object."""
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", settings.database_url)
    return config


def upgrade(revision: str = "head") -> None:
    """Upgrade database to specified revision."""
    config = get_alembic_config()
    command.upgrade(config, revision)
    print(f"✅ Database upgraded to revision: {revision}")


def downgrade(revision: str = "-1") -> None:
    """Downgrade database by specified steps."""
    config = get_alembic_config()
    command.downgrade(config, revision)
    print(f"⬇️  Database downgraded by: {revision} revision(s)")


def history() -> None:
    """Show migration history."""
    config = get_alembic_config()
    command.history(config)


def current() -> None:
    """Show current migration revision."""
    config = get_alembic_config()
    command.current(config)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "upgrade":
        revision = sys.argv[2] if len(sys.argv) > 2 else "head"
        upgrade(revision)
    elif cmd == "downgrade":
        revision = sys.argv[2] if len(sys.argv) > 2 else "-1"
        downgrade(revision)
    elif cmd == "history":
        history()
    elif cmd == "current":
        current()
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)