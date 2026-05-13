"""Add Google OAuth2 support

Revision ID: 003_google_oauth2
Revises: 002_totp_2fa
Create Date: 2026-05-14 17:00:00.000000+00:00
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '003_google_oauth2'
down_revision: Union[str, Sequence[str]] = '002_totp_2fa'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add Google sub column to users (for linking Google OAuth2 accounts)
    op.add_column('users', sa.Column('google_sub', sa.String(255), nullable=True))
    op.create_index('idx_users_google_sub', 'users', ['google_sub'])


def downgrade() -> None:
    op.drop_index('idx_users_google_sub', table_name='users')
    op.drop_column('users', 'google_sub')