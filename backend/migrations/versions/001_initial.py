"""Initial migration — create all tables.

Revision ID: 001_initial
Revises:
Create Date: 2026-05-13
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Users table
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column("email", sa.String(100), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), server_default="viewer", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_login", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
        sa.UniqueConstraint("email"),
    )

    # IOCs table
    op.create_table(
        "iocs",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("threat_level", sa.String(20), server_default="medium", nullable=False),
        sa.Column("confidence", sa.Integer(), server_default="50", nullable=False),
        sa.Column("source", sa.String(255), nullable=True),
        sa.Column("first_seen", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_seen", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False),
        sa.Column("stix_id", sa.String(255), nullable=True),
        sa.Column("created_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("value", "type", name="uq_ioc_value_type"),
    )

    # Threat actors table
    op.create_table(
        "threat_actors",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("aliases", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("actor_types", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("sophistication", sa.String(100), nullable=True),
        sa.Column("resource_level", sa.String(100), nullable=True),
        sa.Column("goals", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("motivation", sa.String(255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("stix_id", sa.String(255), nullable=True),
        sa.Column("active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    # Malware table
    op.create_table(
        "malware",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("aliases", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("malware_types", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("is_family", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("stix_id", sa.String(255), nullable=True),
        sa.Column("first_seen", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_seen", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # Campaigns table
    op.create_table(
        "campaigns",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("campaign_types", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("objective", sa.Text(), nullable=True),
        sa.Column("first_seen", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_seen", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("stix_id", sa.String(255), nullable=True),
        sa.Column("created_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # Feeds table
    op.create_table(
        "feeds",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("feed_type", sa.String(50), server_default="taxii", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("last_ingestion", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False),
        sa.Column("created_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # Attack mappings table
    op.create_table(
        "attack_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("ioc_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("tactic", sa.String(50), nullable=False),
        sa.Column("technique_name", sa.String(255), nullable=False),
        sa.Column("confidence", sa.Integer(), server_default="0", nullable=False),
        sa.Column("source", sa.String(255), server_default="manual", nullable=False),
        sa.Column("created_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ioc_id", "technique_id", name="uq_ioc_technique"),
        sa.ForeignKeyConstraint(["ioc_id"], ["iocs.id"], name="fk_attack_mapping_ioc", ondelete="CASCADE"),
    )

    # Audit logs table
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("resource", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.String(100), nullable=True),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("timestamp", postgresql.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_audit_user", ondelete="SET NULL"),
    )

    # Indexes
    op.create_index("idx_iocs_type", "iocs", ["type"], unique=False)
    op.create_index("idx_iocs_value", "iocs", ["value"], unique=False)
    op.create_index("idx_iocs_threat_level", "iocs", ["threat_level"], unique=False)
    op.create_index("idx_iocs_active", "iocs", ["active"], unique=False)
    op.create_index("idx_actors_name", "threat_actors", ["name"], unique=False)
    op.create_index("idx_malware_name", "malware", ["name"], unique=False)
    op.create_index("idx_campaigns_name", "campaigns", ["name"], unique=False)
    op.create_index("idx_audit_timestamp", "audit_logs", ["timestamp"], unique=False)
    op.create_index("idx_audit_user", "audit_logs", ["username"], unique=False)


def downgrade() -> None:
    op.drop_index("idx_audit_user", table_name="audit_logs")
    op.drop_index("idx_audit_timestamp", table_name="audit_logs")
    op.drop_index("idx_campaigns_name", table_name="campaigns")
    op.drop_index("idx_malware_name", table_name="malware")
    op.drop_index("idx_actors_name", table_name="threat_actors")
    op.drop_index("idx_iocs_active", table_name="iocs")
    op.drop_index("idx_iocs_threat_level", table_name="iocs")
    op.drop_index("idx_iocs_value", table_name="iocs")
    op.drop_index("idx_iocs_type", table_name="iocs")
    op.drop_table("audit_logs")
    op.drop_table("attack_mappings")
    op.drop_table("feeds")
    op.drop_table("campaigns")
    op.drop_table("malware")
    op.drop_table("threat_actors")
    op.drop_table("iocs")
    op.drop_table("users")