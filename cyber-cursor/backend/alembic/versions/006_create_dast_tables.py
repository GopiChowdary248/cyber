"""Create DAST tables

Revision ID: 006
Revises: 005_add_comprehensive_sast_models
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '006'
down_revision = '005_add_comprehensive_sast_models'
branch_labels = None
depends_on = None


def upgrade():
    # Create DAST projects table
    op.create_table('dast_projects',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('target_urls', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('scope_config', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create DAST scan profiles table
    op.create_table('dast_scan_profiles',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('modules', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('settings', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('is_default', sa.Boolean(), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['project_id'], ['dast_projects.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_id', 'name', name='uq_scan_profile_name_per_project')
    )
    
    # Create DAST scans table
    op.create_table('dast_scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('profile_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('target_urls', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('progress', sa.Float(), nullable=True),
        sa.Column('total_requests', sa.Integer(), nullable=True),
        sa.Column('completed_requests', sa.Integer(), nullable=True),
        sa.Column('issues_found', sa.Integer(), nullable=True),
        sa.Column('scan_config', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['profile_id'], ['dast_scan_profiles.id'], ),
        sa.ForeignKeyConstraint(['project_id'], ['dast_projects.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint('progress >= 0.0 AND progress <= 100.0', name='chk_scan_progress')
    )
    
    # Create DAST scan issues table
    op.create_table('dast_scan_issues',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('type', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('url', sa.String(length=2000), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('cwe_id', sa.String(length=20), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['dast_scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint('confidence >= 0.0 AND confidence <= 100.0', name='chk_issue_confidence'),
        sa.CheckConstraint('cvss_score >= 0.0 AND cvss_score <= 10.0', name='chk_cvss_score')
    )
    
    # Create DAST HTTP entries table
    op.create_table('dast_http_entries',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('url', sa.String(length=2000), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(length=10), nullable=False),
        sa.Column('request_headers', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('request_body', sa.Text(), nullable=True),
        sa.Column('request_params', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('request_size', sa.Integer(), nullable=True),
        sa.Column('response_headers', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('response_body', sa.Text(), nullable=True),
        sa.Column('response_size', sa.Integer(), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('content_type', sa.String(length=100), nullable=True),
        sa.Column('duration', sa.Integer(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('highlighted', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['dast_projects.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create DAST crawl results table
    op.create_table('dast_crawl_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('url', sa.String(length=2000), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('content_type', sa.String(length=100), nullable=True),
        sa.Column('title', sa.String(length=500), nullable=True),
        sa.Column('depth', sa.Integer(), nullable=True),
        sa.Column('parent_url', sa.String(length=2000), nullable=True),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('last_accessed', sa.DateTime(timezone=True), nullable=True),
        sa.Column('in_scope', sa.Boolean(), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['dast_projects.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create DAST match/replace rules table
    op.create_table('dast_match_replace_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('match_pattern', sa.String(length=1000), nullable=False),
        sa.Column('replace_pattern', sa.String(length=1000), nullable=False),
        sa.Column('match_type', sa.String(length=50), nullable=True),
        sa.Column('apply_to', sa.String(length=50), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['project_id'], ['dast_projects.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create DAST intruder attacks table
    op.create_table('dast_intruder_attacks',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('target_url', sa.String(length=2000), nullable=False),
        sa.Column('attack_type', sa.String(length=50), nullable=False),
        sa.Column('payload_sets', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('positions', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('progress', sa.Float(), nullable=True),
        sa.Column('total_requests', sa.Integer(), nullable=True),
        sa.Column('completed_requests', sa.Integer(), nullable=True),
        sa.Column('successful_requests', sa.Integer(), nullable=True),
        sa.Column('failed_requests', sa.Integer(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['project_id'], ['dast_projects.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint('progress >= 0.0 AND progress <= 100.0', name='chk_intruder_progress')
    )
    
    # Create DAST intruder results table
    op.create_table('dast_intruder_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('attack_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('payload', sa.String(length=1000), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('response_size', sa.Integer(), nullable=True),
        sa.Column('response_time', sa.Integer(), nullable=True),
        sa.Column('response_headers', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('response_body', sa.Text(), nullable=True),
        sa.Column('content_type', sa.String(length=100), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('highlighted', sa.Boolean(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['attack_id'], ['dast_intruder_attacks.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create DAST repeater requests table
    op.create_table('dast_repeater_requests',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('url', sa.String(length=2000), nullable=False),
        sa.Column('headers', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('body', sa.Text(), nullable=True),
        sa.Column('params', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['project_id'], ['dast_projects.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create DAST repeater responses table
    op.create_table('dast_repeater_responses',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('request_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('headers', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('body', sa.Text(), nullable=True),
        sa.Column('content_type', sa.String(length=100), nullable=True),
        sa.Column('size', sa.Integer(), nullable=True),
        sa.Column('duration', sa.Integer(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['request_id'], ['dast_repeater_requests.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create DAST audit logs table
    op.create_table('dast_audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=False),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['dast_projects.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create DAST user permissions table
    op.create_table('dast_user_permissions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False),
        sa.Column('permissions', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('granted_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('granted_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['granted_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['project_id'], ['dast_projects.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'project_id', name='uq_user_project_permission'),
        sa.CheckConstraint("role IN ('owner', 'admin', 'user', 'viewer')", name='chk_valid_role')
    )
    
    # Create DAST project settings table
    op.create_table('dast_project_settings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('proxy_settings', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('scanner_settings', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('crawler_settings', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('notification_settings', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('security_settings', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['dast_projects.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_id', name='uq_project_settings_project_id')
    )
    
    # Create DAST notifications table
    op.create_table('dast_notifications',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('type', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('read', sa.Boolean(), nullable=True),
        sa.Column('action_url', sa.String(length=2000), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['dast_projects.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for better performance
    op.create_index('idx_dast_projects_created_by', 'dast_projects', ['created_by'])
    op.create_index('idx_dast_projects_status', 'dast_projects', ['status'])
    op.create_index('idx_dast_projects_created_at', 'dast_projects', ['created_at'])
    
    op.create_index('idx_scan_profiles_project_id', 'dast_scan_profiles', ['project_id'])
    op.create_index('idx_scan_profiles_is_default', 'dast_scan_profiles', ['is_default'])
    
    op.create_index('idx_dast_scans_project_id', 'dast_scans', ['project_id'])
    op.create_index('idx_dast_scans_status', 'dast_scans', ['status'])
    op.create_index('idx_dast_scans_created_by', 'dast_scans', ['created_by'])
    op.create_index('idx_dast_scans_started_at', 'dast_scans', ['started_at'])
    
    op.create_index('idx_scan_issues_scan_id', 'dast_scan_issues', ['scan_id'])
    op.create_index('idx_scan_issues_type', 'dast_scan_issues', ['type'])
    op.create_index('idx_scan_issues_severity', 'dast_scan_issues', ['severity'])
    op.create_index('idx_scan_issues_status', 'dast_scan_issues', ['status'])
    op.create_index('idx_scan_issues_discovered_at', 'dast_scan_issues', ['discovered_at'])
    
    op.create_index('idx_http_entries_project_id', 'dast_http_entries', ['project_id'])
    op.create_index('idx_http_entries_method', 'dast_http_entries', ['method'])
    op.create_index('idx_http_entries_status_code', 'dast_http_entries', ['status_code'])
    op.create_index('idx_http_entries_host', 'dast_http_entries', ['host'])
    op.create_index('idx_http_entries_timestamp', 'dast_http_entries', ['timestamp'])
    
    op.create_index('idx_crawl_results_project_id', 'dast_crawl_results', ['project_id'])
    op.create_index('idx_crawl_results_url', 'dast_crawl_results', ['url'])
    op.create_index('idx_crawl_results_depth', 'dast_crawl_results', ['depth'])
    op.create_index('idx_crawl_results_in_scope', 'dast_crawl_results', ['in_scope'])
    op.create_index('idx_crawl_results_discovered_at', 'dast_crawl_results', ['discovered_at'])
    
    op.create_index('idx_match_replace_rules_project_id', 'dast_match_replace_rules', ['project_id'])
    op.create_index('idx_match_replace_rules_enabled', 'dast_match_replace_rules', ['enabled'])
    op.create_index('idx_match_replace_rules_priority', 'dast_match_replace_rules', ['priority'])
    
    op.create_index('idx_intruder_attacks_project_id', 'dast_intruder_attacks', ['project_id'])
    op.create_index('idx_intruder_attacks_status', 'dast_intruder_attacks', ['status'])
    op.create_index('idx_intruder_attacks_attack_type', 'dast_intruder_attacks', ['attack_type'])
    
    op.create_index('idx_intruder_results_attack_id', 'dast_intruder_results', ['attack_id'])
    op.create_index('idx_intruder_results_status_code', 'dast_intruder_results', ['status_code'])
    op.create_index('idx_intruder_results_timestamp', 'dast_intruder_results', ['timestamp'])
    
    op.create_index('idx_repeater_requests_project_id', 'dast_repeater_requests', ['project_id'])
    op.create_index('idx_repeater_requests_method', 'dast_repeater_requests', ['method'])
    op.create_index('idx_repeater_requests_created_at', 'dast_repeater_requests', ['created_at'])
    
    op.create_index('idx_repeater_responses_request_id', 'dast_repeater_responses', ['request_id'])
    op.create_index('idx_repeater_responses_status_code', 'dast_repeater_responses', ['status_code'])
    op.create_index('idx_repeater_responses_timestamp', 'dast_repeater_responses', ['timestamp'])
    
    op.create_index('idx_audit_logs_project_id', 'dast_audit_logs', ['project_id'])
    op.create_index('idx_audit_logs_user_id', 'dast_audit_logs', ['user_id'])
    op.create_index('idx_audit_logs_action', 'dast_audit_logs', ['action'])
    op.create_index('idx_audit_logs_timestamp', 'dast_audit_logs', ['timestamp'])
    
    op.create_index('idx_user_permissions_user_id', 'dast_user_permissions', ['user_id'])
    op.create_index('idx_user_permissions_project_id', 'dast_user_permissions', ['project_id'])
    op.create_index('idx_user_permissions_role', 'dast_user_permissions', ['role'])
    
    op.create_index('idx_project_settings_project_id', 'dast_project_settings', ['project_id'])
    
    op.create_index('idx_notifications_project_id', 'dast_notifications', ['project_id'])
    op.create_index('idx_notifications_user_id', 'dast_notifications', ['user_id'])
    op.create_index('idx_notifications_type', 'dast_notifications', ['type'])
    op.create_index('idx_notifications_severity', 'dast_notifications', ['severity'])
    op.create_index('idx_notifications_read', 'dast_notifications', ['read'])
    op.create_index('idx_notifications_created_at', 'dast_notifications', ['created_at'])


def downgrade():
    # Drop all DAST tables in reverse order
    op.drop_table('dast_notifications')
    op.drop_table('dast_project_settings')
    op.drop_table('dast_user_permissions')
    op.drop_table('dast_audit_logs')
    op.drop_table('dast_repeater_responses')
    op.drop_table('dast_repeater_requests')
    op.drop_table('dast_intruder_results')
    op.drop_table('dast_intruder_attacks')
    op.drop_table('dast_match_replace_rules')
    op.drop_table('dast_crawl_results')
    op.drop_table('dast_http_entries')
    op.drop_table('dast_scan_issues')
    op.drop_table('dast_scans')
    op.drop_table('dast_scan_profiles')
    op.drop_table('dast_projects')
