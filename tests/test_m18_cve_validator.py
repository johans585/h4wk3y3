"""Unit tests for m18 — CVE validator (PURE helpers only).

We test the pure path-resolution and target-building helpers. The nuclei
subprocess runner (`_run_nuclei`) and the DB-backed `validate()` orchestrator
are NOT exercised here — they require the nuclei binary / a real DB and are out
of scope for pure unit tests (see module-level note below).

What IS isolable and tested:
  - `_resolve_template`  : maps a stored relative template path → absolute path
                           on disk, with the http/cves → network/cves fallback.
                           Uses a tmp_path sandbox, no network/binary.
  - `_target_from_asset` : builds a probe URL from asset_url / asset_host,
                           preferring a full URL and stripping trailing slashes.
"""
import os


from modules import m18_cve_validator as m18
from modules.m18_cve_validator import DEFAULT_NUCLEI_TEMPLATES_DIR


# ─── _target_from_asset (pure) ──────────────────────────────────────────────
class TestTargetFromAsset:
    def test_prefers_full_url(self):
        assert m18._target_from_asset("https://www.una.bj/app", "una.bj") \
            == "https://www.una.bj/app"

    def test_strips_trailing_slash(self):
        assert m18._target_from_asset("https://una.bj/", None) == "https://una.bj"

    def test_falls_back_to_host_https(self):
        assert m18._target_from_asset(None, "una.bj") == "https://una.bj"

    def test_url_without_scheme_falls_back_to_host(self):
        # asset_url lacks '://' → treated as unusable, host used instead.
        assert m18._target_from_asset("una.bj/path", "host.example") \
            == "https://host.example"

    def test_url_without_scheme_and_no_host(self):
        assert m18._target_from_asset("una.bj/path", None) is None

    def test_all_none(self):
        assert m18._target_from_asset(None, None) is None


# ─── _resolve_template (pure filesystem, no binary) ─────────────────────────
class TestResolveTemplate:
    def test_resolves_existing_http_cves(self, tmp_path):
        rel = "http/cves/2021/CVE-2021-41773.yaml"
        full = tmp_path / rel
        full.parent.mkdir(parents=True)
        full.write_text("id: CVE-2021-41773\n")
        resolved = m18._resolve_template(rel, base_dir=str(tmp_path))
        assert resolved == str(full)
        assert os.path.isfile(resolved)

    def test_network_cves_fallback(self, tmp_path):
        # File only exists under network/cves but is referenced as http/cves.
        rel = "http/cves/2020/CVE-2020-0001.yaml"
        actual = tmp_path / "network/cves/2020/CVE-2020-0001.yaml"
        actual.parent.mkdir(parents=True)
        actual.write_text("id: x\n")
        resolved = m18._resolve_template(rel, base_dir=str(tmp_path))
        assert resolved == str(actual)

    def test_returns_none_when_missing(self, tmp_path):
        resolved = m18._resolve_template(
            "http/cves/2099/CVE-2099-9999.yaml", base_dir=str(tmp_path))
        assert resolved is None

    def test_empty_template_rel(self, tmp_path):
        assert m18._resolve_template("", base_dir=str(tmp_path)) is None
        assert m18._resolve_template(None, base_dir=str(tmp_path)) is None


def test_default_templates_dir_constant():
    # Sanity guard on the documented default path.
    assert DEFAULT_NUCLEI_TEMPLATES_DIR.endswith("nuclei-templates")
