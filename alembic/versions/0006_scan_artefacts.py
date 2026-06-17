"""scan_artefacts : structured per-module output in Postgres (JSONB)

Promotes the per-item structured module outputs that historically lived only
as JSON files under output/<domain>/ (js_secrets, js_endpoints, takeovers,
patterns, tech, email_security, …) into a single queryable table.

Rationale (see core/orm.py ScanArtefact):
  - One source of truth for the dashboard's specialised views (they used to
    read the disk copy, which could drift from the DB findings).
  - Diff/history/scoping for free via (domain, module, kind, dedup_key)
    cross-scan identity + first/last_seen_scan_id, mirroring findings.
  - `data` is JSONB (deliberately breaking the Text-JSON convention used by
    the rest of the schema) because queryability is the whole point —
    Postgres-only runtime makes JSONB safe.

Additive, reversible. No destructive change.

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-04
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = '0006'
down_revision: Union[str, Sequence[str], None] = '0005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scan_artefacts',
        sa.Column('id',                 sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('scan_id',            sa.Text(),    nullable=False),
        sa.Column('domain',             sa.Text(),    nullable=False),
        sa.Column('module',             sa.Text(),    nullable=False),   # 'm11'
        sa.Column('kind',               sa.Text(),    nullable=False),   # 'js_secret'
        sa.Column('dedup_key',          sa.Text(),    nullable=False),
        sa.Column('data',               postgresql.JSONB(), nullable=False),
        sa.Column('first_seen_scan_id', sa.Text(),    nullable=True),
        sa.Column('last_seen_scan_id',  sa.Text(),    nullable=True),
        sa.Column('created_at',         sa.Text(),    nullable=False),
        sa.Column('updated_at',         sa.Text(),    nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'domain', 'module', 'kind', 'dedup_key',
            name='uq_scan_artefacts_identity',
        ),
    )
    with op.batch_alter_table('scan_artefacts', schema=None) as batch_op:
        batch_op.create_index('idx_scan_artefacts_domain_kind', ['domain', 'kind'])
        batch_op.create_index('idx_scan_artefacts_scan',        ['scan_id'])
        batch_op.create_index('idx_scan_artefacts_last_seen',
                              ['domain', 'kind', 'last_seen_scan_id'])


def downgrade() -> None:
    with op.batch_alter_table('scan_artefacts', schema=None) as batch_op:
        batch_op.drop_index('idx_scan_artefacts_last_seen')
        batch_op.drop_index('idx_scan_artefacts_scan')
        batch_op.drop_index('idx_scan_artefacts_domain_kind')
    op.drop_table('scan_artefacts')
