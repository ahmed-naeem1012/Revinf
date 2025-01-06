"""Initial migration

Revision ID: abc123456789
Revises: None
Create Date: 2025-01-06 18:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# Revision identifiers, used by Alembic.
revision = 'abc123456789'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create the User table
    op.create_table(
        'user',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('first_name', sa.String(50), nullable=False),
        sa.Column('email', sa.String(255), nullable=False, unique=True),
        sa.Column('password', sa.String(255), nullable=False),
        sa.Column('is_verified', sa.Boolean, nullable=False, default=False),
        sa.Column('verification_token', sa.String(255), nullable=True),
        sa.Column('token_expires_at', sa.DateTime, nullable=True),
    )

    # Create the OTP table
    op.create_table(
        'otp',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id', ondelete='CASCADE'), nullable=False),
        sa.Column('code', sa.String(6), nullable=False),
        sa.Column('expires_at', sa.DateTime, nullable=False),
    )


def downgrade():
    # Drop the OTP table
    op.drop_table('otp')

    # Drop the User table
    op.drop_table('user')
