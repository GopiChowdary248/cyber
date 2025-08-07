"""Initial SAST models with comprehensive functionality

Revision ID: 001
Revises: 
Create Date: 2025-08-04 21:41:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Add missing columns to sast_scans table
    op.add_column('sast_scans', sa.Column('lines_of_code', sa.Integer(), nullable=True))
    op.add_column('sast_scans', sa.Column('lines_of_comment', sa.Integer(), nullable=True))
    op.add_column('sast_scans', sa.Column('duplicated_lines', sa.Integer(), nullable=True))
    op.add_column('sast_scans', sa.Column('duplicated_blocks', sa.Integer(), nullable=True))
    op.add_column('sast_scans', sa.Column('uncovered_lines', sa.Integer(), nullable=True))
    op.add_column('sast_scans', sa.Column('uncovered_conditions', sa.Integer(), nullable=True))
    op.add_column('sast_scans', sa.Column('debt_ratio', sa.Float(), nullable=True))
    
    # Add missing columns to sast_projects table
    op.add_column('sast_projects', sa.Column('lines_of_code', sa.Integer(), nullable=True))
    op.add_column('sast_projects', sa.Column('coverage', sa.Float(), nullable=True))
    op.add_column('sast_projects', sa.Column('technical_debt', sa.Integer(), nullable=True))
    op.add_column('sast_projects', sa.Column('debt_ratio', sa.Float(), nullable=True))
    
    # Note: All SAST tables and enum types already exist in the database
    # This migration only adds missing columns to existing tables


def downgrade():
    # Drop added columns from sast_projects table
    op.drop_column('sast_projects', 'debt_ratio')
    op.drop_column('sast_projects', 'technical_debt')
    op.drop_column('sast_projects', 'coverage')
    op.drop_column('sast_projects', 'lines_of_code')
    
    # Drop added columns from sast_scans table
    op.drop_column('sast_scans', 'debt_ratio')
    op.drop_column('sast_scans', 'uncovered_conditions')
    op.drop_column('sast_scans', 'uncovered_lines')
    op.drop_column('sast_scans', 'duplicated_blocks')
    op.drop_column('sast_scans', 'duplicated_lines')
    op.drop_column('sast_scans', 'lines_of_comment')
    op.drop_column('sast_scans', 'lines_of_code') 