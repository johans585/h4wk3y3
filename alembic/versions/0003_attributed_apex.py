"""attribution : attributed_apex on subdomains, live_hosts, findings

Adds a nullable TEXT column + index on each of the 3 asset tables to
record the most-specific apex (from `targets.apex`) that owns a given
host/finding. Set by the post-scan attribution hook (longest-suffix
match). NULL = orphan / shadow-IT candidate.

Additive migration, no FK, no destructive change. Existing rows stay
NULL until backfilled (cf. scripts/backfill_attribution.py).

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-21
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0003'
down_revision: Union[str, Sequence[str], None] = '0002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('subdomains', schema=None) as batch_op:
        batch_op.add_column(sa.Column('attributed_apex', sa.Text(), nullable=True))
        batch_op.create_index(
            'idx_subdomains_attributed_apex', ['attributed_apex'], unique=False,
        )

    with op.batch_alter_table('live_hosts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('attributed_apex', sa.Text(), nullable=True))
        batch_op.create_index(
            'idx_live_hosts_attributed_apex', ['attributed_apex'], unique=False,
        )

    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('attributed_apex', sa.Text(), nullable=True))
        batch_op.create_index(
            'idx_findings_attributed_apex', ['attributed_apex'], unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index('idx_findings_attributed_apex')
        batch_op.drop_column('attributed_apex')

    with op.batch_alter_table('live_hosts', schema=None) as batch_op:
        batch_op.drop_index('idx_live_hosts_attributed_apex')
        batch_op.drop_column('attributed_apex')

    with op.batch_alter_table('subdomains', schema=None) as batch_op:
        batch_op.drop_index('idx_subdomains_attributed_apex')
        batch_op.drop_column('attributed_apex')
