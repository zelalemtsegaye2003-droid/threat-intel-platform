"""Add TOTP 2FA support

Revision ID: 002_totp_2fa
Revises: 001_initial
Create Date: 2026-05-14 16:00:00.000000+00:00
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '002_totp_2fa'
down_revision: Union[str, None] = '001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add TOTP secret column to users table
    op.add_column('users', sa.Column('totp_secret', sa.String(64), nullable=True))

    # Create recovery codes table
    op.create_table(
        'user_recovery_codes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('code_hash', sa.String(255), nullable=False),
        sa.Column('used', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_recovery_codes_user', 'user_recovery_codes', ['user_id'])
    op.create_index('idx_recovery_codes_used', 'user_recovery_codes', ['used'])


def downgrade() -> None:
    op.drop_index('idx_recovery_codes_used', table_name='user_recovery_codes')
    op.drop_index('idx_recovery_codes_user', table_name='user_recovery_codes')
    op.drop_table('user_recovery_codes')
    op.drop_column('users', 'totp_secret')