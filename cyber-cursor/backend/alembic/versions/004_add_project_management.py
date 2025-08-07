"""Add project management tables

Revision ID: 004
Revises: 001
Create Date: 2024-01-15 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '004'
down_revision = '001'
branch_labels = None
depends_on = None

def upgrade():
    # Create enum types if they don't exist
    op.execute("DO $$ BEGIN CREATE TYPE projecttype AS ENUM ('sast', 'dast', 'rasp', 'cloud', 'general'); EXCEPTION WHEN duplicate_object THEN null; END $$;")
    op.execute("DO $$ BEGIN CREATE TYPE repositorytype AS ENUM ('git', 'svn', 'zip', 'local'); EXCEPTION WHEN duplicate_object THEN null; END $$;")
    op.execute("DO $$ BEGIN CREATE TYPE projectstatus AS ENUM ('active', 'inactive', 'archived', 'deleted'); EXCEPTION WHEN duplicate_object THEN null; END $$;")
    
    # Create projects table
    op.create_table('projects',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('key', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('project_type', sa.String(length=50), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('repository_type', sa.String(length=50), nullable=True),
        sa.Column('repository_url', sa.String(length=500), nullable=True),
        sa.Column('repository_branch', sa.String(length=100), nullable=True),
        sa.Column('repository_username', sa.String(length=255), nullable=True),
        sa.Column('repository_token', sa.String(length=500), nullable=True),
        sa.Column('source_path', sa.String(length=500), nullable=True),
        sa.Column('language', sa.String(length=50), nullable=True),
        sa.Column('framework', sa.String(length=100), nullable=True),
        sa.Column('tags', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('security_level', sa.String(length=50), nullable=True),
        sa.Column('compliance_frameworks', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('last_scan', sa.DateTime(), nullable=True),
        sa.Column('last_sync', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_projects_id'), 'projects', ['id'], unique=False)
    op.create_index(op.f('ix_projects_key'), 'projects', ['key'], unique=True)
    op.create_index(op.f('ix_projects_name'), 'projects', ['name'], unique=False)
    
    # Create teams table
    op.create_table('teams',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('team_type', sa.String(length=50), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_teams_id'), 'teams', ['id'], unique=False)
    
    # Create team_members table
    op.create_table('team_members',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=True),
        sa.Column('joined_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_team_members_id'), 'team_members', ['id'], unique=False)
    
    # Create project_scans table
    op.create_table('project_scans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('scan_type', sa.String(length=50), nullable=False),
        sa.Column('scan_name', sa.String(length=255), nullable=False),
        sa.Column('scan_config', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('progress', sa.Integer(), nullable=True),
        sa.Column('total_issues', sa.Integer(), nullable=True),
        sa.Column('critical_issues', sa.Integer(), nullable=True),
        sa.Column('high_issues', sa.Integer(), nullable=True),
        sa.Column('medium_issues', sa.Integer(), nullable=True),
        sa.Column('low_issues', sa.Integer(), nullable=True),
        sa.Column('scan_duration', sa.Integer(), nullable=True),
        sa.Column('files_scanned', sa.Integer(), nullable=True),
        sa.Column('lines_scanned', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('error_details', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('started_by', sa.Integer(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ),
        sa.ForeignKeyConstraint(['started_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_project_scans_id'), 'project_scans', ['id'], unique=False)
    
    # Create project_issues table
    op.create_table('project_issues',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('issue_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('recommendation', sa.Text(), nullable=True),
        sa.Column('file_path', sa.String(length=500), nullable=True),
        sa.Column('line_number', sa.Integer(), nullable=True),
        sa.Column('start_line', sa.Integer(), nullable=True),
        sa.Column('end_line', sa.Integer(), nullable=True),
        sa.Column('cwe_id', sa.String(length=20), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('owasp_category', sa.String(length=100), nullable=True),
        sa.Column('assigned_to', sa.Integer(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ),
        sa.ForeignKeyConstraint(['scan_id'], ['project_scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_project_issues_id'), 'project_issues', ['id'], unique=False)
    
    # Add team_id foreign key to projects table
    op.create_foreign_key(None, 'projects', 'teams', ['team_id'], ['id'])

def downgrade():
    # Remove foreign key constraints
    op.drop_constraint(None, 'projects', type_='foreignkey')
    
    # Drop tables
    op.drop_index(op.f('ix_project_issues_id'), table_name='project_issues')
    op.drop_table('project_issues')
    
    op.drop_index(op.f('ix_project_scans_id'), table_name='project_scans')
    op.drop_table('project_scans')
    
    op.drop_index(op.f('ix_team_members_id'), table_name='team_members')
    op.drop_table('team_members')
    
    op.drop_index(op.f('ix_teams_id'), table_name='teams')
    op.drop_table('teams')
    
    op.drop_index(op.f('ix_projects_name'), table_name='projects')
    op.drop_index(op.f('ix_projects_key'), table_name='projects')
    op.drop_index(op.f('ix_projects_id'), table_name='projects')
    op.drop_table('projects')
    
    # Drop enum types
    op.execute("DROP TYPE projectstatus")
    op.execute("DROP TYPE repositorytype")
    op.execute("DROP TYPE projecttype") 