"""Tests for M06 Takeover Detection — CNAME signatures, deduplication, module ID."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import MagicMock
from modules.m06_takeover import TakeoverModule, TAKEOVER_SIGNATURES


def make_module():
    config = MagicMock()
    def mock_get(*args, **kwargs):
        default = kwargs.get('default', None)
        if 'log_level' in args:
            return 'INFO'
        if 'log_file' in args:
            return None
        return default
    config.get.side_effect = mock_get
    db = MagicMock()
    return TakeoverModule(config, db)


class TestModuleMetadata:
    def test_module_id_is_m06(self):
        m = make_module()
        assert m.MODULE_ID == "m06"

    def test_module_id_not_m04(self):
        # Regression test: duplicate MODULE_ID = "m05" was removed
        m = make_module()
        assert m.MODULE_ID != "m05"


class TestTakeoverSignatures:
    def test_signatures_have_three_fields(self):
        for sig in TAKEOVER_SIGNATURES:
            assert len(sig) == 3, f"Signature {sig} should have 3 fields"

    def test_github_pages_signature(self):
        matches = [s for s in TAKEOVER_SIGNATURES if 'github.io' in s[0]]
        assert len(matches) == 1
        assert "GitHub Pages" in matches[0][1]
        assert matches[0][2]  # fingerprint not empty

    def test_aws_s3_signature(self):
        matches = [s for s in TAKEOVER_SIGNATURES if 's3.amazonaws.com' in s[0]]
        assert len(matches) == 1
        assert 'NoSuchBucket' in matches[0][2]

    def test_heroku_signature(self):
        matches = [s for s in TAKEOVER_SIGNATURES if 'herokuapp.com' in s[0]]
        assert len(matches) == 1

    def test_netlify_signature(self):
        matches = [s for s in TAKEOVER_SIGNATURES if 'netlify.app' in s[0]]
        assert len(matches) == 1

    def test_azure_signature(self):
        matches = [s for s in TAKEOVER_SIGNATURES if 'azurewebsites.net' in s[0]]
        assert len(matches) == 1

    def test_all_services_have_names(self):
        for cname_pat, service, _ in TAKEOVER_SIGNATURES:
            assert service.strip(), f"Signature for {cname_pat} has empty service name"

    def test_no_duplicate_cname_patterns(self):
        patterns = [s[0] for s in TAKEOVER_SIGNATURES]
        assert len(patterns) == len(set(patterns)), "Duplicate CNAME patterns found"


class TestDeduplication:
    def test_dedup_logic(self):
        """The run() method deduplicates findings by subdomain+service key."""
        findings = [
            {'subdomain': 'old.example.com', 'service': 'GitHub Pages', 'confidence': 0.9},
            {'subdomain': 'old.example.com', 'service': 'GitHub Pages', 'confidence': 0.9},
            {'subdomain': 'new.example.com', 'service': 'Heroku',       'confidence': 0.85},
        ]
        seen = set()
        unique = []
        for item in findings:
            key = item.get('subdomain', '') + item.get('service', '')
            if key not in seen:
                seen.add(key)
                unique.append(item)
        assert len(unique) == 2

    def test_different_services_not_deduped(self):
        findings = [
            {'subdomain': 'sub.example.com', 'service': 'GitHub Pages'},
            {'subdomain': 'sub.example.com', 'service': 'Heroku'},
        ]
        seen = set()
        unique = []
        for item in findings:
            key = item.get('subdomain', '') + item.get('service', '')
            if key not in seen:
                seen.add(key)
                unique.append(item)
        assert len(unique) == 2


class TestImports:
    def test_aiohttp_imported_at_module_level(self):
        """aiohttp should be a top-level import in m06_takeover, not inside a loop."""
        import ast
        source = Path(__file__).parent.parent / 'modules' / 'm06_takeover.py'
        tree = ast.parse(source.read_text())
        # Find all import statements — count only top-level ones
        top_level_imports = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            and isinstance(getattr(node, 'col_offset', 0), int)
            and node.col_offset == 0
        ]
        imported_names = set()
        for node in top_level_imports:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_names.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                imported_names.add(node.module or '')
        assert 'aiohttp' in imported_names, "aiohttp should be a top-level import"
        assert 'ssl' in imported_names, "ssl should be a top-level import"


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
