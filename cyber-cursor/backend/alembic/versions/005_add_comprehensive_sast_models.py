"""Add comprehensive SAST models for SonarQube-like functionality

Revision ID: 005
Revises: 004
Create Date: 2025-08-05 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None

def upgrade():
    # Create enum types for new SAST models
    op.execute("DO $$ BEGIN CREATE TYPE issueresolution AS ENUM ('UNRESOLVED', 'FIXED', 'FALSE_POSITIVE', 'WON_FIX', 'REMOVED'); EXCEPTION WHEN duplicate_object THEN null; END $$;")
    op.execute("DO $$ BEGIN CREATE TYPE securityhotspotresolution AS ENUM ('FIXED', 'SAFE', 'ACKNOWLEDGED'); EXCEPTION WHEN duplicate_object THEN null; END $$;")
    op.execute("DO $$ BEGIN CREATE TYPE securityhotspotstatus AS ENUM ('TO_REVIEW', 'REVIEWED', 'SAFE', 'FIXED'); EXCEPTION WHEN duplicate_object THEN null; END $$;")
    
    # Create SAST Duplication tables
    op.create_table('sast_duplications',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('file_path', sa.String(), nullable=False),
        sa.Column('duplicated_lines', sa.Integer(), nullable=False),
        sa.Column('duplicated_blocks', sa.Integer(), nullable=False),
        sa.Column('duplication_density', sa.Float(), nullable=False),
        sa.Column('language', sa.String(), nullable=False),
        sa.Column('last_modified', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.ForeignKeyConstraint(['scan_id'], ['sast_scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_duplications_id'), 'sast_duplications', ['id'], unique=False)
    
    op.create_table('sast_duplication_blocks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('duplication_id', sa.Integer(), nullable=False),
        sa.Column('file_path', sa.String(), nullable=False),
        sa.Column('start_line', sa.Integer(), nullable=False),
        sa.Column('end_line', sa.Integer(), nullable=False),
        sa.Column('code_snippet', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['duplication_id'], ['sast_duplications.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_duplication_blocks_id'), 'sast_duplication_blocks', ['id'], unique=False)
    
    # Create SAST Security Report tables
    op.create_table('sast_security_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('overall_security_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=False),
        sa.Column('security_score', sa.Integer(), nullable=False),
        sa.Column('vulnerabilities_count', sa.Integer(), nullable=False),
        sa.Column('critical_vulnerabilities', sa.Integer(), nullable=False),
        sa.Column('major_vulnerabilities', sa.Integer(), nullable=False),
        sa.Column('minor_vulnerabilities', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.ForeignKeyConstraint(['scan_id'], ['sast_scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_security_reports_id'), 'sast_security_reports', ['id'], unique=False)
    
    op.create_table('sast_owasp_mappings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('security_report_id', sa.Integer(), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.Column('severity', sa.Enum('BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO', name='issueseverity'), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['security_report_id'], ['sast_security_reports.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_owasp_mappings_id'), 'sast_owasp_mappings', ['id'], unique=False)
    
    op.create_table('sast_cwe_mappings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('security_report_id', sa.Integer(), nullable=False),
        sa.Column('cwe_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.Column('severity', sa.Enum('BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO', name='issueseverity'), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['security_report_id'], ['sast_security_reports.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_cwe_mappings_id'), 'sast_cwe_mappings', ['id'], unique=False)
    
    # Create SAST Reliability Report tables
    op.create_table('sast_reliability_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('reliability_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=False),
        sa.Column('bug_count', sa.Integer(), nullable=False),
        sa.Column('bug_density', sa.Float(), nullable=False),
        sa.Column('new_bugs', sa.Integer(), nullable=False),
        sa.Column('resolved_bugs', sa.Integer(), nullable=False),
        sa.Column('blocker_bugs', sa.Integer(), nullable=False),
        sa.Column('critical_bugs', sa.Integer(), nullable=False),
        sa.Column('major_bugs', sa.Integer(), nullable=False),
        sa.Column('minor_bugs', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.ForeignKeyConstraint(['scan_id'], ['sast_scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_reliability_reports_id'), 'sast_reliability_reports', ['id'], unique=False)
    
    op.create_table('sast_bug_categories',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('reliability_report_id', sa.Integer(), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['reliability_report_id'], ['sast_reliability_reports.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_bug_categories_id'), 'sast_bug_categories', ['id'], unique=False)
    
    # Create SAST Maintainability Report tables
    op.create_table('sast_maintainability_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('maintainability_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=False),
        sa.Column('code_smell_count', sa.Integer(), nullable=False),
        sa.Column('code_smell_density', sa.Float(), nullable=False),
        sa.Column('complexity', sa.Float(), nullable=False),
        sa.Column('cognitive_complexity', sa.Float(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.ForeignKeyConstraint(['scan_id'], ['sast_scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_maintainability_reports_id'), 'sast_maintainability_reports', ['id'], unique=False)
    
    op.create_table('sast_code_smell_categories',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('maintainability_report_id', sa.Integer(), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['maintainability_report_id'], ['sast_maintainability_reports.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_code_smell_categories_id'), 'sast_code_smell_categories', ['id'], unique=False)
    
    # Create SAST Activity tables
    op.create_table('sast_activities',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('activity_type', sa.String(), nullable=False),
        sa.Column('author', sa.String(), nullable=False),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('activity_metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_activities_id'), 'sast_activities', ['id'], unique=False)
    
    op.create_table('sast_contributors',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('commits_count', sa.Integer(), nullable=True),
        sa.Column('issues_count', sa.Integer(), nullable=True),
        sa.Column('hotspots_count', sa.Integer(), nullable=True),
        sa.Column('last_activity', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_contributors_id'), 'sast_contributors', ['id'], unique=False)
    
    # Create SAST Project Settings tables
    op.create_table('sast_project_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('scan_schedule', sa.String(), nullable=True),
        sa.Column('auto_scan', sa.Boolean(), nullable=True),
        sa.Column('quality_profile', sa.String(), nullable=True),
        sa.Column('quality_gate', sa.String(), nullable=True),
        sa.Column('exclusions', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('notifications_email', sa.Boolean(), nullable=True),
        sa.Column('notifications_slack', sa.Boolean(), nullable=True),
        sa.Column('notifications_webhook', sa.String(), nullable=True),
        sa.Column('integration_github', sa.Boolean(), nullable=True),
        sa.Column('integration_gitlab', sa.Boolean(), nullable=True),
        sa.Column('integration_bitbucket', sa.Boolean(), nullable=True),
        sa.Column('integration_jenkins', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_project_settings_id'), 'sast_project_settings', ['id'], unique=False)
    
    op.create_table('sast_project_permissions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('group_name', sa.String(), nullable=True),
        sa.Column('role', sa.String(), nullable=False),
        sa.Column('permissions', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_project_permissions_id'), 'sast_project_permissions', ['id'], unique=False)
    
    # Create SAST Project Metrics and Trends tables
    op.create_table('sast_project_metrics',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('lines_of_code', sa.Integer(), nullable=False),
        sa.Column('files_count', sa.Integer(), nullable=False),
        sa.Column('functions_count', sa.Integer(), nullable=False),
        sa.Column('classes_count', sa.Integer(), nullable=False),
        sa.Column('complexity', sa.Float(), nullable=False),
        sa.Column('maintainability_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=False),
        sa.Column('security_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=False),
        sa.Column('reliability_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=False),
        sa.Column('coverage', sa.Float(), nullable=False),
        sa.Column('duplication_density', sa.Float(), nullable=False),
        sa.Column('total_issues', sa.Integer(), nullable=False),
        sa.Column('bugs_count', sa.Integer(), nullable=False),
        sa.Column('vulnerabilities_count', sa.Integer(), nullable=False),
        sa.Column('code_smells_count', sa.Integer(), nullable=False),
        sa.Column('security_hotspots_count', sa.Integer(), nullable=False),
        sa.Column('total_debt', sa.Integer(), nullable=False),
        sa.Column('debt_ratio', sa.Float(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.ForeignKeyConstraint(['scan_id'], ['sast_scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_project_metrics_id'), 'sast_project_metrics', ['id'], unique=False)
    
    op.create_table('sast_project_trends',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('date', sa.Date(), nullable=False),
        sa.Column('total_issues', sa.Integer(), nullable=False),
        sa.Column('bugs_count', sa.Integer(), nullable=False),
        sa.Column('vulnerabilities_count', sa.Integer(), nullable=False),
        sa.Column('code_smells_count', sa.Integer(), nullable=False),
        sa.Column('coverage', sa.Float(), nullable=False),
        sa.Column('duplication_density', sa.Float(), nullable=False),
        sa.Column('complexity', sa.Float(), nullable=False),
        sa.Column('maintainability_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=False),
        sa.Column('security_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=False),
        sa.Column('reliability_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_project_trends_id'), 'sast_project_trends', ['id'], unique=False)
    
    # Create SAST Rules table
    op.create_table('sast_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('rule_id', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=100), nullable=False),
        sa.Column('subcategory', sa.String(length=100), nullable=True),
        sa.Column('severity', sa.Enum('BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO', name='issueseverity'), nullable=False),
        sa.Column('type', sa.Enum('BUG', 'VULNERABILITY', 'CODE_SMELL', 'SECURITY_HOTSPOT', name='issuetype'), nullable=False),
        sa.Column('cwe_id', sa.String(length=20), nullable=True),
        sa.Column('owasp_category', sa.String(length=100), nullable=True),
        sa.Column('tags', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('effort', sa.Integer(), nullable=True),
        sa.Column('languages', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_rules_id'), 'sast_rules', ['id'], unique=False)
    op.create_index(op.f('ix_sast_rules_rule_id'), 'sast_rules', ['rule_id'], unique=True)
    
    # Create SAST Quality Gate table
    op.create_table('sast_quality_gates',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('max_blocker_issues', sa.Integer(), nullable=True),
        sa.Column('max_critical_issues', sa.Integer(), nullable=True),
        sa.Column('max_major_issues', sa.Integer(), nullable=True),
        sa.Column('max_minor_issues', sa.Integer(), nullable=True),
        sa.Column('max_info_issues', sa.Integer(), nullable=True),
        sa.Column('min_coverage', sa.Float(), nullable=True),
        sa.Column('min_branch_coverage', sa.Float(), nullable=True),
        sa.Column('max_debt_ratio', sa.Float(), nullable=True),
        sa.Column('max_technical_debt', sa.Integer(), nullable=True),
        sa.Column('max_duplicated_lines', sa.Integer(), nullable=True),
        sa.Column('max_duplicated_blocks', sa.Integer(), nullable=True),
        sa.Column('min_maintainability_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=True),
        sa.Column('min_security_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=True),
        sa.Column('min_reliability_rating', sa.Enum('A', 'B', 'C', 'D', 'E', name='rating'), nullable=True),
        sa.Column('status', sa.Enum('PASSED', 'FAILED', 'WARN', name='qualitygatestatus'), nullable=True),
        sa.Column('last_evaluation', sa.DateTime(), nullable=True),
        sa.Column('evaluation_results', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_quality_gates_id'), 'sast_quality_gates', ['id'], unique=False)
    
    # Create SAST Project Configuration table
    op.create_table('sast_project_configurations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('scan_patterns', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('excluded_files', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('excluded_directories', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('enabled_rules', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('disabled_rules', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('rule_severities', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('quality_gate_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['sast_projects.id'], ),
        sa.ForeignKeyConstraint(['quality_gate_id'], ['sast_quality_gates.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sast_project_configurations_id'), 'sast_project_configurations', ['id'], unique=False)


def downgrade():
    # Drop tables in reverse order
    op.drop_index(op.f('ix_sast_project_configurations_id'), table_name='sast_project_configurations')
    op.drop_table('sast_project_configurations')
    
    op.drop_index(op.f('ix_sast_quality_gates_id'), table_name='sast_quality_gates')
    op.drop_table('sast_quality_gates')
    
    op.drop_index(op.f('ix_sast_rules_rule_id'), table_name='sast_rules')
    op.drop_index(op.f('ix_sast_rules_id'), table_name='sast_rules')
    op.drop_table('sast_rules')
    
    op.drop_index(op.f('ix_sast_project_trends_id'), table_name='sast_project_trends')
    op.drop_table('sast_project_trends')
    
    op.drop_index(op.f('ix_sast_project_metrics_id'), table_name='sast_project_metrics')
    op.drop_table('sast_project_metrics')
    
    op.drop_index(op.f('ix_sast_project_permissions_id'), table_name='sast_project_permissions')
    op.drop_table('sast_project_permissions')
    
    op.drop_index(op.f('ix_sast_project_settings_id'), table_name='sast_project_settings')
    op.drop_table('sast_project_settings')
    
    op.drop_index(op.f('ix_sast_contributors_id'), table_name='sast_contributors')
    op.drop_table('sast_contributors')
    
    op.drop_index(op.f('ix_sast_activities_id'), table_name='sast_activities')
    op.drop_table('sast_activities')
    
    op.drop_index(op.f('ix_sast_code_smell_categories_id'), table_name='sast_code_smell_categories')
    op.drop_table('sast_code_smell_categories')
    
    op.drop_index(op.f('ix_sast_maintainability_reports_id'), table_name='sast_maintainability_reports')
    op.drop_table('sast_maintainability_reports')
    
    op.drop_index(op.f('ix_sast_bug_categories_id'), table_name='sast_bug_categories')
    op.drop_table('sast_bug_categories')
    
    op.drop_index(op.f('ix_sast_reliability_reports_id'), table_name='sast_reliability_reports')
    op.drop_table('sast_reliability_reports')
    
    op.drop_index(op.f('ix_sast_cwe_mappings_id'), table_name='sast_cwe_mappings')
    op.drop_table('sast_cwe_mappings')
    
    op.drop_index(op.f('ix_sast_owasp_mappings_id'), table_name='sast_owasp_mappings')
    op.drop_table('sast_owasp_mappings')
    
    op.drop_index(op.f('ix_sast_security_reports_id'), table_name='sast_security_reports')
    op.drop_table('sast_security_reports')
    
    op.drop_index(op.f('ix_sast_duplication_blocks_id'), table_name='sast_duplication_blocks')
    op.drop_table('sast_duplication_blocks')
    
    op.drop_index(op.f('ix_sast_duplications_id'), table_name='sast_duplications')
    op.drop_table('sast_duplications')
    
    # Drop enum types
    op.execute("DROP TYPE IF EXISTS securityhotspotstatus")
    op.execute("DROP TYPE IF EXISTS securityhotspotresolution")
    op.execute("DROP TYPE IF EXISTS issueresolution") 