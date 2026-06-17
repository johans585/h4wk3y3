"""CVE intelligence : cves + cve_matches + surface_intel

Founds the CVE chantier (Étape 2.6-ish) — three tables that hold :
  - cves           : the CVE catalogue (NVD + KEV + EPSS feeds + nuclei mapping)
  - cve_matches    : per-asset attribution (internal live_hosts OR external Shodan/Censys)
  - surface_intel  : cache of surface engine observations (Shodan/Censys/Fofa/…)

Schema rationale :
  - JSON-encoded text columns (cpes, products, refs, payload, …) for
    consistency with the rest of the Argus schema (it already encodes
    `findings.tags`, `live_hosts.technologies`, `audit_log.details` etc.
    as Text-JSON). Postgres-only runtime so JSONB would work too, but
    keeping the convention.
  - All FKs are ON DELETE SET NULL (CVE row can vanish if a feed retracts,
    matches stay for history with NULL ref).
  - 3-strategies match supported : `nuclei_template`, `product_version`,
    `product_name_only`, plus `surface_shodan`/`surface_censys` etc. for
    external observations.

Additive, reversible. No destructive change.

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-22
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0004'
down_revision: Union[str, Sequence[str], None] = '0003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. cves : référentiel ─────────────────────────────────────────
    op.create_table(
        'cves',
        sa.Column('cve_id',          sa.Text(),    nullable=False),
        sa.Column('published_at',    sa.Text(),    nullable=True),
        sa.Column('cvss_v3',         sa.Float(),   nullable=True),   # 0..10
        sa.Column('cvss_v3_vector',  sa.Text(),    nullable=True),
        sa.Column('cvss_v2',         sa.Float(),   nullable=True),
        sa.Column('epss',            sa.Float(),   nullable=True),   # 0..1 (EPSS)
        sa.Column('epss_percentile', sa.Float(),   nullable=True),
        sa.Column('kev_flag',        sa.Integer(), nullable=False,
                                     server_default=sa.text('0')),
        sa.Column('kev_added_at',    sa.Text(),    nullable=True),
        sa.Column('kev_ransomware',  sa.Integer(), nullable=False,
                                     server_default=sa.text('0')),
        sa.Column('description',     sa.Text(),    nullable=True),
        sa.Column('vendor',          sa.Text(),    nullable=True),
        sa.Column('cpes',            sa.Text(),    nullable=True),   # JSON list
        sa.Column('products',        sa.Text(),    nullable=True),   # JSON [{vendor,product,version_constraint}]
        sa.Column('refs',            sa.Text(),    nullable=True),   # JSON list URLs
        sa.Column('nuclei_template', sa.Text(),    nullable=True),
        sa.Column('source_feeds',    sa.Text(),    nullable=True),   # JSON ["nvd","kev","epss"]
        sa.Column('created_at',      sa.Text(),    nullable=False),
        sa.Column('updated_at',      sa.Text(),    nullable=False),
        sa.PrimaryKeyConstraint('cve_id'),
    )
    with op.batch_alter_table('cves', schema=None) as batch_op:
        batch_op.create_index('idx_cves_published_at', ['published_at'])
        batch_op.create_index('idx_cves_cvss_v3',      ['cvss_v3'])
        batch_op.create_index('idx_cves_epss',         ['epss'])
        batch_op.create_index('idx_cves_kev_flag',     ['kev_flag'])
        batch_op.create_index('idx_cves_vendor',       ['vendor'])

    # ── 2. surface_intel : cache des observations Shodan/Censys/… ────
    op.create_table(
        'surface_intel',
        sa.Column('id',              sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('source',          sa.Text(),    nullable=False),    # shodan|censys|...
        sa.Column('ip',              sa.Text(),    nullable=False),    # stored as text (Postgres INET would force casts)
        sa.Column('port',            sa.Integer(), nullable=True),
        sa.Column('product',         sa.Text(),    nullable=True),
        sa.Column('version',         sa.Text(),    nullable=True),
        sa.Column('banner_snippet',  sa.Text(),    nullable=True),
        sa.Column('country',         sa.Text(),    nullable=True),
        sa.Column('asn',             sa.Integer(), nullable=True),
        sa.Column('org_name_raw',    sa.Text(),    nullable=True),
        sa.Column('cve_ids',         sa.Text(),    nullable=True),     # JSON list (source-reported)
        sa.Column('hostnames',       sa.Text(),    nullable=True),     # JSON list (reverse DNS / hostnames)
        sa.Column('ssl_san',         sa.Text(),    nullable=True),     # JSON list cert SANs
        sa.Column('ptr',             sa.Text(),    nullable=True),
        sa.Column('payload',         sa.Text(),    nullable=True),     # JSON raw response (audit)
        # Pivot
        sa.Column('attributed_apex', sa.Text(),    nullable=True),
        sa.Column('pivot_method',    sa.Text(),    nullable=True),     # cert_san|ptr|asn|netblock|...
        sa.Column('observed_at',     sa.Text(),    nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('surface_intel', schema=None) as batch_op:
        batch_op.create_index('idx_surface_intel_source',     ['source'])
        batch_op.create_index('idx_surface_intel_ip',         ['ip'])
        batch_op.create_index('idx_surface_intel_ip_port',    ['ip', 'port'])
        batch_op.create_index('idx_surface_intel_country',    ['country'])
        batch_op.create_index('idx_surface_intel_asn',        ['asn'])
        batch_op.create_index('idx_surface_intel_product',    ['product'])
        batch_op.create_index('idx_surface_intel_attributed', ['attributed_apex'])

    # ── 3. cve_matches : asset ↔ CVE ─────────────────────────────────
    op.create_table(
        'cve_matches',
        sa.Column('id',                sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('cve_id',            sa.Text(),    nullable=False),
        # Méthode de matching
        sa.Column('match_method',      sa.Text(),    nullable=False),  # nuclei_template|product_version|product_name_only|surface_shodan|surface_censys
        sa.Column('match_source',      sa.Text(),    nullable=False),  # internal|external
        # Asset (au moins un de host/ip/url renseigné)
        sa.Column('asset_host',        sa.Text(),    nullable=True),
        sa.Column('asset_ip',          sa.Text(),    nullable=True),
        sa.Column('asset_url',         sa.Text(),    nullable=True),
        sa.Column('asset_port',        sa.Integer(), nullable=True),
        sa.Column('asset_product',     sa.Text(),    nullable=True),
        sa.Column('asset_version',     sa.Text(),    nullable=True),   # version observée si dispo
        sa.Column('version_required',  sa.Text(),    nullable=True),   # contrainte CVE ex "< 14.2.10"
        # Attribution
        sa.Column('attributed_apex',   sa.Text(),    nullable=True),
        sa.Column('organisation_id',   sa.Integer(), nullable=True),
        sa.Column('pivot_method',      sa.Text(),    nullable=True),
        # Statut
        sa.Column('confidence',        sa.Float(),   nullable=False, server_default=sa.text('0.5')),
        sa.Column('validation_state',  sa.Text(),    nullable=False, server_default=sa.text("'candidate'")),
        sa.Column('validated_at',      sa.Text(),    nullable=True),
        sa.Column('validated_by',      sa.Text(),    nullable=True),
        sa.Column('evidence',          sa.Text(),    nullable=True),   # JSON
        # Temporel
        sa.Column('first_seen_at',     sa.Text(),    nullable=False),
        sa.Column('last_seen_at',      sa.Text(),    nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(
            ['cve_id'], ['cves.cve_id'],
            ondelete='CASCADE',
            name='fk_cve_matches_cve_id',
        ),
        sa.ForeignKeyConstraint(
            ['organisation_id'], ['organisations.id'],
            ondelete='SET NULL',
            name='fk_cve_matches_organisation',
        ),
        # Idempotence : un même (CVE, asset, méthode) ne se duplique pas
        sa.UniqueConstraint(
            'cve_id', 'asset_url', 'asset_ip', 'asset_port', 'match_method',
            name='uq_cve_matches_target_method',
        ),
    )
    with op.batch_alter_table('cve_matches', schema=None) as batch_op:
        batch_op.create_index('idx_cve_matches_cve_id',           ['cve_id'])
        batch_op.create_index('idx_cve_matches_attributed',       ['attributed_apex'])
        batch_op.create_index('idx_cve_matches_organisation',     ['organisation_id'])
        batch_op.create_index('idx_cve_matches_validation_state', ['validation_state'])
        batch_op.create_index('idx_cve_matches_match_source',     ['match_source'])


def downgrade() -> None:
    with op.batch_alter_table('cve_matches', schema=None) as batch_op:
        batch_op.drop_index('idx_cve_matches_match_source')
        batch_op.drop_index('idx_cve_matches_validation_state')
        batch_op.drop_index('idx_cve_matches_organisation')
        batch_op.drop_index('idx_cve_matches_attributed')
        batch_op.drop_index('idx_cve_matches_cve_id')
    op.drop_table('cve_matches')

    with op.batch_alter_table('surface_intel', schema=None) as batch_op:
        batch_op.drop_index('idx_surface_intel_attributed')
        batch_op.drop_index('idx_surface_intel_product')
        batch_op.drop_index('idx_surface_intel_asn')
        batch_op.drop_index('idx_surface_intel_country')
        batch_op.drop_index('idx_surface_intel_ip_port')
        batch_op.drop_index('idx_surface_intel_ip')
        batch_op.drop_index('idx_surface_intel_source')
    op.drop_table('surface_intel')

    with op.batch_alter_table('cves', schema=None) as batch_op:
        batch_op.drop_index('idx_cves_vendor')
        batch_op.drop_index('idx_cves_kev_flag')
        batch_op.drop_index('idx_cves_epss')
        batch_op.drop_index('idx_cves_cvss_v3')
        batch_op.drop_index('idx_cves_published_at')
    op.drop_table('cves')
