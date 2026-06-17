"""multi-org : organisations + targets

Étape 2.1 — adds two new tables. No destructive changes on existing tables.
Resolution domain → target → organisation is done in queries (no FK added
on scans/findings/etc to keep this migration idempotent + reversible).

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-16
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0002'
down_revision: Union[str, Sequence[str], None] = '0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'organisations',
        sa.Column('id',         sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name',       sa.Text(),    nullable=False),
        sa.Column('h1_handle',  sa.Text(),    nullable=True),
        sa.Column('scope_file', sa.Text(),    nullable=True),
        sa.Column('notes',      sa.Text(),    nullable=True),
        sa.Column('created_at', sa.Text(),    nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name', name='uq_organisations_name'),
    )
    with op.batch_alter_table('organisations', schema=None) as batch_op:
        batch_op.create_index('idx_organisations_name', ['name'], unique=False)

    op.create_table(
        'targets',
        sa.Column('apex',                 sa.Text(),    nullable=False),
        sa.Column('organisation_id',      sa.Integer(), nullable=True),
        sa.Column('scope_file_override',  sa.Text(),    nullable=True),
        sa.Column('notes',                sa.Text(),    nullable=True),
        sa.Column('created_at',           sa.Text(),    nullable=False),
        sa.PrimaryKeyConstraint('apex'),
        sa.ForeignKeyConstraint(
            ['organisation_id'], ['organisations.id'],
            ondelete='SET NULL',
            name='fk_targets_organisation',
        ),
    )
    with op.batch_alter_table('targets', schema=None) as batch_op:
        batch_op.create_index('idx_targets_org', ['organisation_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('targets', schema=None) as batch_op:
        batch_op.drop_index('idx_targets_org')
    op.drop_table('targets')

    with op.batch_alter_table('organisations', schema=None) as batch_op:
        batch_op.drop_index('idx_organisations_name')
    op.drop_table('organisations')
