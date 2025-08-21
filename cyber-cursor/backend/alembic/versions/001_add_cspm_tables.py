"""Add CSPM tables

Revision ID: 001
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create asset_relationships table
    op.create_table('asset_relationships',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('parent_asset_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('child_asset_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('relationship_type', sa.String(length=100), nullable=False),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['child_asset_id'], ['assets.id'], ),
        sa.ForeignKeyConstraint(['parent_asset_id'], ['assets.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create policy_evaluation_results table
    op.create_table('policy_evaluation_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('evaluation_date', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('result', sa.Boolean(), nullable=False),
        sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('execution_time_ms', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create compliance_controls table
    op.create_table('compliance_controls',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('framework_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('control_id', sa.String(length=100), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('requirements', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('policy_mappings', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create compliance_mappings table
    op.create_table('compliance_mappings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('control_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('mapping_type', sa.String(length=50), nullable=True),
        sa.Column('confidence_score', sa.Numeric(precision=3, scale=2), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['control_id'], ['compliance_controls.id'], ),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create integration_webhooks table
    op.create_table('integration_webhooks',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('integration_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('webhook_url', sa.String(length=500), nullable=False),
        sa.Column('secret_key', sa.String(length=255), nullable=True),
        sa.Column('events', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('last_delivery', sa.DateTime(timezone=True), nullable=True),
        sa.Column('delivery_count', sa.Integer(), nullable=True),
        sa.Column('failure_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['integration_id'], ['integrations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create scan_templates table
    op.create_table('scan_templates',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('scan_config', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('schedule', sa.String(length=100), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create remediation_playbooks table
    op.create_table('remediation_playbooks',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('steps', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('prerequisites', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('estimated_time', sa.Integer(), nullable=True),
        sa.Column('risk_level', sa.String(length=50), nullable=True),
        sa.Column('auto_approval', sa.Boolean(), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create remediation_executions table
    op.create_table('remediation_executions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('playbook_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('executed_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('execution_log', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('result', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ),
        sa.ForeignKeyConstraint(['playbook_id'], ['remediation_playbooks.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create risk_assessments table
    op.create_table('risk_assessments',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('assessment_date', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('overall_score', sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column('factors', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('recommendations', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('assessed_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for better performance
    op.create_index('ix_asset_relationships_parent_asset_id', 'asset_relationships', ['parent_asset_id'])
    op.create_index('ix_asset_relationships_child_asset_id', 'asset_relationships', ['child_asset_id'])
    op.create_index('ix_policy_evaluation_results_asset_id', 'policy_evaluation_results', ['asset_id'])
    op.create_index('ix_policy_evaluation_results_policy_id', 'policy_evaluation_results', ['policy_id'])
    op.create_index('ix_compliance_controls_framework_id', 'compliance_controls', ['framework_id'])
    op.create_index('ix_compliance_mappings_control_id', 'compliance_mappings', ['control_id'])
    op.create_index('ix_compliance_mappings_policy_id', 'compliance_mappings', ['policy_id'])
    op.create_index('ix_scan_templates_project_id', 'scan_templates', ['project_id'])
    op.create_index('ix_remediation_executions_playbook_id', 'remediation_executions', ['playbook_id'])
    op.create_index('ix_remediation_executions_finding_id', 'remediation_executions', ['finding_id'])
    op.create_index('ix_risk_assessments_asset_id', 'risk_assessments', ['asset_id'])


def downgrade():
    # Drop indexes
    op.drop_index('ix_risk_assessments_asset_id', table_name='risk_assessments')
    op.drop_index('ix_remediation_executions_finding_id', table_name='remediation_executions')
    op.drop_index('ix_remediation_executions_playbook_id', table_name='remediation_executions')
    op.drop_index('ix_scan_templates_project_id', table_name='scan_templates')
    op.drop_index('ix_compliance_mappings_policy_id', table_name='compliance_mappings')
    op.drop_index('ix_compliance_mappings_control_id', table_name='compliance_mappings')
    op.drop_index('ix_compliance_controls_framework_id', table_name='compliance_controls')
    op.drop_index('ix_policy_evaluation_results_policy_id', table_name='policy_evaluation_results')
    op.drop_index('ix_policy_evaluation_results_asset_id', table_name='policy_evaluation_results')
    op.drop_index('ix_asset_relationships_child_asset_id', table_name='asset_relationships')
    op.drop_index('ix_asset_relationships_parent_asset_id', table_name='asset_relationships')
    
    # Drop tables
    op.drop_table('risk_assessments')
    op.drop_table('remediation_executions')
    op.drop_table('remediation_playbooks')
    op.drop_table('scan_templates')
    op.drop_table('integration_webhooks')
    op.drop_table('compliance_mappings')
    op.drop_table('compliance_controls')
    op.drop_table('policy_evaluation_results')
    op.drop_table('asset_relationships')
