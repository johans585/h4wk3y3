"""Unit tests for the dashboard scan manager."""
import pytest

from dashboard.backend.scan_manager import (
    ScanManager,
    ScanRun,
    MODES,
    MODULE_CATALOG,
    is_valid_domain,
)


def test_modes_has_custom():
    assert "custom" in MODES
    assert MODES["custom"] is None  # custom is dynamic, no pre-set argv

def test_module_catalog_complete():
    ids = [m[0] for m in MODULE_CATALOG]
    assert "m02" in ids
    assert "m14" in ids
    assert len(ids) == len(set(ids)), "Duplicate module IDs in catalog"

def test_module_catalog_format():
    for entry in MODULE_CATALOG:
        assert len(entry) == 4, "Catalog entries must be (id, label, desc, deps)"
        mid, label, desc, deps = entry
        assert isinstance(deps, list)


class TestDomainValidation:
    def test_valid_simple(self):
        assert is_valid_domain("example.com")

    def test_valid_subdomain(self):
        assert is_valid_domain("sub.example.com")

    def test_valid_multi_level(self):
        assert is_valid_domain("a.b.c.example.com")

    @pytest.mark.parametrize("bad", [
        "", "no_dot", "spaces in name.com", "https://example.com",
        "example.com/path", "example..com", ".example.com", "-example.com",
        "example-.com", "*",
    ])
    def test_invalid(self, bad):
        assert not is_valid_domain(bad)


class TestScanRun:
    def test_slot_includes_modules(self):
        run = ScanRun(target='x.com', mode='custom', modules=['m02', 'm12'])
        assert run.modules == ['m02', 'm12']

    def test_default_modules_empty(self):
        run = ScanRun(target='x.com', mode='full')
        assert run.modules == []

    def test_to_dict_exposes_modules(self):
        run = ScanRun(target='x.com', mode='custom', modules=['m02'])
        d = run.to_dict()
        assert d['modules'] == ['m02']
        assert d['target'] == 'x.com'
        assert d['mode'] == 'custom'


class TestScanManager:
    @pytest.fixture
    def mgr(self, tmp_path):
        return ScanManager(project_root=tmp_path, allow_remote=False, wildcards=[])

    def test_unknown_mode_rejected(self, mgr):
        run, err = mgr.start("example.com", mode="bogus")
        assert run is None
        assert "unknown mode" in err

    def test_custom_without_modules_rejected(self, mgr):
        run, err = mgr.start("example.com", mode="custom")
        assert run is None
        assert "non-empty" in err.lower()

    def test_custom_invalid_module_rejected(self, mgr):
        run, err = mgr.start("example.com", mode="custom", modules=["m99"])
        assert run is None
        assert "invalid module" in err

    def test_custom_module_normalises(self, mgr):
        # Inputs are lower-cased + deduped while preserving first-seen order.
        # NOTE: actual scan won't run because subprocess will fail without h4wk3y3.py
        # but the validation passes and a run object is created.
        run, err = mgr.start("example.com", mode="custom", modules=["m02", "M01", "m02"])
        assert err is None
        assert run is not None
        assert run.modules == ["m02", "m01"]
        # cleanup: terminate the spurious thread
        if run._thread:
            run._thread.join(timeout=2)

    def test_invalid_target_rejected(self, mgr):
        run, err = mgr.start("not a domain!", mode="full")
        assert run is None
        assert "invalid" in err.lower()

    def test_remote_bind_accepts_any_valid_domain(self, tmp_path):
        # The wildcards allow-list was removed: ScanManager now only checks
        # syntax. Network-level scoping is the operator's responsibility
        # (firewall, reverse-proxy auth, VPN-only access). This test guards
        # against a regression that re-introduces the gate silently.
        mgr = ScanManager(project_root=tmp_path, allow_remote=True,
                          wildcards=["allowed.com"])
        run, err = mgr.start("sub.allowed.com", mode="full")
        assert err is None
        if run and run._thread:
            run._thread.join(timeout=2)

        run, err = mgr.start("not-allowed.com", mode="full")
        assert err is None  # no longer gated
        if run and run._thread:
            run._thread.join(timeout=2)
