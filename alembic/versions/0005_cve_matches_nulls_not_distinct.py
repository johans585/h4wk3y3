"""cve_matches UNIQUE constraint with NULLS NOT DISTINCT

Bug fix : PostgreSQL traite NULL != NULL dans les UNIQUE constraints par
défaut. Comme `asset_ip` est toujours NULL pour les matches internal, la
contrainte `uq_cve_matches_target_method` ne dédup pas et le correlator
re-insère 856 matches à chaque exécution → table gonfle.

Fix : drop l'ancienne contrainte, recréer avec NULLS NOT DISTINCT (PG 15+).
Avant le drop, on assume que les data ont déjà été truncate-ées
(scripts/cve_correlate.py les rebuilt en quelques secondes).

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-22
"""
from typing import Sequence, Union

from alembic import op


revision: str = '0005'
down_revision: Union[str, Sequence[str], None] = '0004'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Drop old constraint and the auto-generated index that backs it.
    op.execute("ALTER TABLE cve_matches DROP CONSTRAINT IF EXISTS uq_cve_matches_target_method")
    # Recreate with NULLS NOT DISTINCT — required for PG to dedup rows
    # where some of the unique-key columns are NULL.
    op.execute("""
        ALTER TABLE cve_matches
          ADD CONSTRAINT uq_cve_matches_target_method
          UNIQUE NULLS NOT DISTINCT
          (cve_id, asset_url, asset_ip, asset_port, match_method)
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE cve_matches DROP CONSTRAINT IF EXISTS uq_cve_matches_target_method")
    op.execute("""
        ALTER TABLE cve_matches
          ADD CONSTRAINT uq_cve_matches_target_method
          UNIQUE (cve_id, asset_url, asset_ip, asset_port, match_method)
    """)
