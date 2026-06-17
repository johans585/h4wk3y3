"""
Tests pour Pipeline :
- Sélection de modules
- Ordre d'exécution
- Gestion erreurs module manquant
- Archive scan précédent
"""
import sys
import tempfile
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))

import pytest

from core.pipeline import Pipeline
from core.config import ArgusConfig
from core.models import ScanTarget


@pytest.fixture
def tmp_db(db):
    """Postgres-backed ArgusDB — alias for the `db` fixture from conftest.

    Argus est Postgres-only depuis le switch 2026-05. L'ancien tempfile SQLite
    a été retiré ; les tests reçoivent maintenant une DB PG TRUNCATEd entre
    chaque cas."""
    return db


@pytest.fixture
def tmp_config():
    cfg = ArgusConfig()
    with tempfile.TemporaryDirectory() as tmp:
        cfg._data.setdefault('general', {})['output_dir'] = tmp
        yield cfg


class TestModuleSelection:
    def test_all_modules_selected_when_none_specified(self, tmp_config, tmp_db):
        p = Pipeline(tmp_config, tmp_db)
        selected = p._select_modules(None)
        ids = [m[0] for m in selected]
        assert 'm02' in ids
        assert 'm03' in ids
        assert 'm12' in ids

    def test_subset_selection(self, tmp_config, tmp_db):
        p = Pipeline(tmp_config, tmp_db)
        selected = p._select_modules(['m02', 'm03'])
        ids = [m[0] for m in selected]
        assert ids == ['m02', 'm03']
        assert 'm12' not in ids

    def test_stages_cover_expected_modules(self, tmp_config, tmp_db):
        # _staged_ids() is derived from STAGES; everything except m02 must
        # be dispatched there (m02 runs in the pre-stage pass).
        staged = Pipeline._staged_ids()
        for mid in ('m03', 'm10', 'm04', 'm05', 'm11', 'm06', 'm12', 'm13', 'm14'):
            assert mid in staged, f"{mid} missing from STAGES"
        assert 'm02' not in staged

    def test_m03_m04_m06_share_parallel_stage(self, tmp_config, tmp_db):
        # m04/m05/m06 share a parallel stage post-m03 (all live_hosts readers).
        parallel_stage = next(
            (s for s in Pipeline.STAGES if isinstance(s, tuple) and 'm06' in s),
            None,
        )
        assert parallel_stage is not None
        assert 'm04' in parallel_stage
        assert 'm05' in parallel_stage

    def test_unknown_module_ignored(self, tmp_config, tmp_db):
        p = Pipeline(tmp_config, tmp_db)
        selected = p._select_modules(['m02', 'mXX_fake'])
        ids = [m[0] for m in selected]
        assert 'm02' in ids
        assert 'mXX_fake' not in ids


class TestArchivePrevious:
    def test_archive_creates_prev_file(self, tmp_config, tmp_db):
        p = Pipeline(tmp_config, tmp_db)
        domain = 'test.com'
        out_dir = tmp_config.output_dir(domain)

        # Crée un summary existant
        summary = out_dir / 'scan_summary.json'
        summary.write_text('{"findings": 10}')

        p._archive_previous(domain)

        prev = out_dir / 'scan_summary.prev.json'
        assert prev.exists()
        assert prev.read_text() == '{"findings": 10}'

    def test_archive_no_error_if_no_previous(self, tmp_config, tmp_db):
        p = Pipeline(tmp_config, tmp_db)
        # Dossier vide, pas de summary -> ne doit pas planter
        p._archive_previous('nonexistent.com')


class TestSaveOutput:
    def test_save_output_creates_files(self, tmp_config, tmp_db):
        p = Pipeline(tmp_config, tmp_db)
        target = ScanTarget(domain='example.com')
        from core.models import Finding, FindingType, Severity
        target.add_finding(Finding(
            type=FindingType.SUBDOMAIN, target='example.com',
            title='sub', severity=Severity.INFO, confidence=0.9
        ))
        p._save_output(target)

        out = tmp_config.output_dir('example.com')
        assert (out / 'scan_summary.json').exists()
        assert (out / 'findings.json').exists()

        import json
        summary = json.loads((out / 'scan_summary.json').read_text())
        assert summary['domain'] == 'example.com'
        assert summary['findings'] == 1


# MultiTargetPipeline removed 2026-05-19: h4wk3y3.py loops the single-target
# Pipeline over all domains (see h4wk3y3.py "Pipeline classique — 1 domaine à
# la fois"). The old TestMultiPipeline class tested a code path that no
# longer exists.


# ─────────────────────────────────────────────────────────────────────
# Scope resolution via organisation (Étape 2.1)
# ─────────────────────────────────────────────────────────────────────

class TestPipelineScopeViaOrg:
    """Pipeline.run() must consult the multi-org tables before falling back
    to YAML auto-discovery / wildcards. We test the resolution by calling
    the same helper used by the pipeline (organisation_for_target) plus
    the YAML load path — exercising the full pipeline.run() would require
    mocking every module, which is overkill for this concern."""

    def test_target_override_wins(self, tmp_path, tmp_db):
        from core import organisation as O
        from core.scope import load_scope_yaml
        # Build a YAML scope file owned by the target row
        scope_file = tmp_path / "target-override.yaml"
        scope_file.write_text(
            "organisation: target-only\n"
            "apex: example.com\n"
            "scope:\n  in: ['*.example.com']\n"
        )
        # Org-default scope file pointing somewhere different (we'll ensure
        # it's NOT used).
        O.create_org(tmp_db, "myorg", scope_file="scopes/should-be-ignored.yaml")
        O.link_target(tmp_db, "example.com", "myorg",
                      scope_file_override=str(scope_file))
        # The pipeline checks `scope_file_override` first.
        t = O.get_target(tmp_db, "example.com")
        assert t["scope_file_override"] == str(scope_file)
        sc = load_scope_yaml(t["scope_file_override"], apex_override="example.com")
        assert sc.organisation == "target-only"

    def test_org_scope_file_used_when_no_override(self, tmp_path, tmp_db):
        from core import organisation as O
        from core.scope import load_scope_yaml
        scope_file = tmp_path / "org-default.yaml"
        scope_file.write_text(
            "organisation: myorg\n"
            "apex: example.com\n"
            "scope:\n  in: ['*.example.com']\n  out: ['*.internal.example.com']\n"
        )
        O.create_org(tmp_db, "myorg", scope_file=str(scope_file))
        O.link_target(tmp_db, "example.com", "myorg")
        org = O.organisation_for_target(tmp_db, "example.com")
        assert org is not None and org["scope_file"] == str(scope_file)
        sc = load_scope_yaml(org["scope_file"], apex_override="example.com")
        assert sc.organisation == "myorg"
        assert "*.example.com" in sc.extra_in_scope

    def test_no_org_falls_through(self, tmp_db):
        from core import organisation as O
        assert O.organisation_for_target(tmp_db, "no-link.example") is None
