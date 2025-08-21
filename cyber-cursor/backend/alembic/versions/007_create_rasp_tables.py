"""Create RASP tables

Revision ID: 007
Revises: 006_create_dast_tables
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '007'
down_revision = '006_create_dast_tables'
branch_labels = None
depends_on = None


def upgrade():
    # Create RASP applications table
    op.create_table('rasp_apps',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('repository_url', sa.String(length=2000), nullable=True),
        sa.Column('framework', sa.String(length=100), nullable=True),
        sa.Column('language', sa.String(length=50), nullable=True),
        sa.Column('version', sa.String(length=50), nullable=True),
        sa.Column('environment', sa.String(length=50), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint('risk_score >= 0.0 AND risk_score <= 10.0', name='chk_app_risk_score')
    )
    
    # Create RASP agents table
    op.create_table('rasp_agents',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('app_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('last_heartbeat', sa.DateTime(timezone=True), nullable=True),
        sa.Column('configuration', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['app_id'], ['rasp_apps.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('agent_id', name='uq_agent_id')
    )
    
    # Create RASP policies table
    op.create_table('rasp_policies',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('app_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['app_id'], ['rasp_apps.id'], ),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create RASP rules table
    op.create_table('rasp_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('rule_type', sa.String(length=100), nullable=False),
        sa.Column('pattern', sa.String(length=1000), nullable=True),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('conditions', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['policy_id'], ['rasp_policies.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create RASP incidents table
    op.create_table('rasp_incidents',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('app_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('stack_trace', sa.Text(), nullable=True),
        sa.Column('action_taken', sa.String(length=50), nullable=True),
        sa.Column('blocked', sa.Boolean(), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['app_id'], ['rasp_apps.id'], ),
        sa.ForeignKeyConstraint(['agent_id'], ['rasp_agents.id'], ),
        sa.ForeignKeyConstraint(['rule_id'], ['rasp_rules.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create RASP events table
    op.create_table('rasp_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('app_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('event_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(['app_id'], ['rasp_apps.id'], ),
        sa.ForeignKeyConstraint(['agent_id'], ['rasp_agents.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create RASP traces table
    op.create_table('rasp_traces',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('app_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('session_id', sa.String(length=255), nullable=True),
        sa.Column('trace_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('performance_metrics', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['app_id'], ['rasp_apps.id'], ),
        sa.ForeignKeyConstraint(['agent_id'], ['rasp_agents.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create RASP vulnerabilities table
    op.create_table('rasp_vulnerabilities',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('app_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('cwe_id', sa.String(length=20), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['app_id'], ['rasp_apps.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint('cvss_score >= 0.0 AND cvss_score <= 10.0', name='chk_vuln_cvss_score')
    )
    
    # Create RASP integrations table
    op.create_table('rasp_integrations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('type', sa.String(length=100), nullable=False),
        sa.Column('configuration', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create RASP metrics table
    op.create_table('rasp_metrics',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('app_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('metric_name', sa.String(length=255), nullable=False),
        sa.Column('metric_value', sa.Float(), nullable=False),
        sa.Column('metric_type', sa.String(length=50), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(['app_id'], ['rasp_apps.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for better performance
    op.create_index('ix_rasp_apps_risk_score', 'rasp_apps', ['risk_score'])
    op.create_index('ix_rasp_agents_status', 'rasp_agents', ['status'])
    op.create_index('ix_rasp_incidents_severity', 'rasp_incidents', ['severity'])
    op.create_index('ix_rasp_incidents_status', 'rasp_incidents', ['status'])
    op.create_index('ix_rasp_events_timestamp', 'rasp_events', ['timestamp'])
    op.create_index('ix_rasp_metrics_timestamp', 'rasp_metrics', ['timestamp'])


def downgrade():
    # Drop indexes
    op.drop_index('ix_rasp_metrics_timestamp', 'rasp_metrics')
    op.drop_index('ix_rasp_events_timestamp', 'rasp_events')
    op.drop_index('ix_rasp_incidents_status', 'rasp_incidents')
    op.drop_index('ix_rasp_incidents_severity', 'rasp_incidents')
    op.drop_index('ix_rasp_agents_status', 'rasp_agents')
    op.drop_index('ix_rasp_apps_risk_score', 'rasp_apps')
    
    # Drop tables in reverse order
    op.drop_table('rasp_metrics')
    op.drop_table('rasp_integrations')
    op.drop_table('rasp_vulnerabilities')
    op.drop_table('rasp_traces')
    op.drop_table('rasp_events')
    op.drop_table('rasp_incidents')
    op.drop_table('rasp_rules')
    op.drop_table('rasp_policies')
    op.drop_table('rasp_agents')
    op.drop_table('rasp_apps')
