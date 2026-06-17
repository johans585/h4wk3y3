"""Unit tests for M09 — Active Validation Module."""
import json
import pytest
from unittest.mock import MagicMock

from modules.m14_active import (
    ActiveValidationModule,
    SENSITIVE_PATHS,
)
from core.models import ScanTarget, FindingType

# After the refactor, SENSITIVE_PATHS is a list of (path, good_fingerprint, severity)
# tuples — fingerprints are inlined per-path instead of a separate dict.
_PATH_STRINGS = [entry[0] for entry in SENSITIVE_PATHS]
_PATHS_WITH_FP = {entry[0] for entry in SENSITIVE_PATHS if entry[1] is not None}


@pytest.fixture
def tmp_target(tmp_path):
    t = ScanTarget(domain='example.com', scan_id='scan-test')
    t.live_hosts = [
        {'url': 'https://example.com', 'domain': 'example.com'},
    ]
    return t


@pytest.fixture
def mock_module(tmp_path):
    cfg = MagicMock()
    cfg.get = lambda *a, **k: {} if k.get('default') is None else k['default']
    cfg.output_dir = lambda d: tmp_path
    db = MagicMock()
    return ActiveValidationModule(cfg, db, stealth=False)


class TestM09Module:
    def test_module_id(self):
        assert ActiveValidationModule.MODULE_ID == "m14"

    def test_sensitive_paths_unique(self):
        assert len(_PATH_STRINGS) == len(set(_PATH_STRINGS))

    def test_sensitive_paths_format(self):
        for p in _PATH_STRINGS:
            assert p.startswith('/'), f"{p} should start with /"

    def test_exposure_fingerprints_keys_in_paths(self):
        # Every path that carries a fingerprint must of course belong to the
        # canonical path list. (Trivially true after the refactor, but keeps
        # the test as a guard against accidental schema regressions.)
        for path in _PATHS_WITH_FP:
            assert path in _PATH_STRINGS, f"{path} fingerprint without matching path"


class TestCollectors:
    def test_collect_xss_empty(self, mock_module, tmp_path):
        urls = mock_module._collect_xss_candidates(tmp_path)
        assert urls == []

    def test_collect_xss_priority_reflected(self, mock_module, tmp_path):
        # Reflected URLs should come first.
        (tmp_path / "reflected_params.json").write_text(json.dumps([
            {'url': 'https://t.io/?q=foo', 'param': 'q'},
        ]))
        (tmp_path / "gf_xss.txt").write_text(
            "https://other.com/?p=1\nhttps://t.io/?q=foo\n"
        )
        urls = mock_module._collect_xss_candidates(tmp_path)
        assert urls[0] == 'https://t.io/?q=foo'
        assert 'https://other.com/?p=1' in urls

    def test_collect_open_redirect_filters(self, mock_module, tmp_path):
        # M09 reads gf_redirect.txt (was gf_open-redirect-body.txt before the
        # refactor — that legacy file actually held URLs whose *body* matched
        # a window.location=… pattern, not URLs with redirect query params).
        gf_file = tmp_path / "gf_redirect.txt"
        gf_file.write_text(
            "https://t.io/login?next=/admin\n"          # OK
            "https://t.io/static.css\n"                  # no query → skip
            "https://t.io/?other=ignored\n"              # not a redirect param
        )
        targets = mock_module._collect_open_redirect_urls(tmp_path, apex='t.io')
        assert len(targets) == 1
        assert targets[0][0] == 'https://t.io/login?next=/admin'
        assert targets[0][1] == 'next'

    def test_collect_sqli_handles_missing_files(self, mock_module, tmp_path):
        urls = mock_module._collect_sqli_candidates(tmp_path)
        assert urls == []


class TestRunSafe:
    @pytest.mark.asyncio
    async def test_run_with_no_live_hosts(self, mock_module):
        """No hosts → graceful skip, no exception."""
        t = ScanTarget(domain='example.com', scan_id='x')
        t.live_hosts = []
        await mock_module.run(t)  # must not raise

    @pytest.mark.asyncio
    async def test_run_disabled_via_config(self, tmp_path):
        cfg = MagicMock()
        cfg.get = lambda section, *a, **k: (
            {'enabled': False} if section == 'active_validation'
            else (k['default'] if 'default' in k else {})
        )
        cfg.output_dir = lambda d: tmp_path
        m = ActiveValidationModule(cfg, MagicMock(), stealth=False)
        t = ScanTarget(domain='example.com', scan_id='x')
        t.live_hosts = [{'url': 'https://example.com', 'domain': 'example.com'}]
        await m.run(t)  # must not raise


class TestActiveFindingTypes:
    def test_finding_types_exist(self):
        # The new active types must be in the enum
        assert FindingType.ACTIVE_XSS.value == "active_xss"
        assert FindingType.ACTIVE_SQLI.value == "active_sqli"
        assert FindingType.ACTIVE_OPEN_REDIRECT.value == "active_open_redirect"
        assert FindingType.ACTIVE_FILE_EXPOSURE.value == "active_file_exposure"
