"""
Tests for Étape 1.3 — m14_candidates.json routing.

m12 used to emit every URL-param sniff (xss/sqli/ssrf/lfi/ssti/idor/redirect)
as a `findings.json` entry, polluting the dashboard with non-actionable
candidates. After Étape 1.3:

* URL-source GF matches go to `m14_candidates.json` (consumed by m14).
* Body-source / JS-source matches and reflected URL matches stay in
  `findings.json` as before.
* m14 reads `m14_candidates.json` first, then falls back to legacy
  `gf_<category>.txt` files for back-compat.
"""
import json
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.m12_pattern import (
    _is_url_pattern_candidate,
    _candidate_category,
    URL_SOURCE_GF,
)
from modules.m14_active import _read_candidates


# ──────────────────────────────────────────────────────────────
# _is_url_pattern_candidate — routing decision logic
# ──────────────────────────────────────────────────────────────

class TestCandidateRouting:
    def test_url_source_xss_routed_to_candidate(self):
        m = {'source': 'url', 'pattern': 'xss', 'requires_validation': True,
             'tags': ['xss', 'grep', 'candidate']}
        assert _is_url_pattern_candidate(m) is True

    def test_url_source_sqli_routed_to_candidate(self):
        m = {'source': 'url', 'pattern': 'gf:sqli',
             'requires_validation': True, 'tags': ['sqli']}
        assert _is_url_pattern_candidate(m) is True

    def test_body_source_aws_key_stays_finding(self):
        m = {'source': 'body', 'pattern': 'aws-keys',
             'tags': ['aws-keys', 'grep']}
        assert _is_url_pattern_candidate(m) is False

    def test_reflected_url_match_stays_finding(self):
        """Reflection check promoted this — it's confirmed echo, not guess."""
        m = {'source': 'url', 'pattern': 'xss',
             'requires_validation': False,
             'tags': ['xss', 'grep', 'candidate', 'reflected']}
        assert _is_url_pattern_candidate(m) is False

    def test_url_match_with_validation_false_stays_finding(self):
        m = {'source': 'url', 'pattern': 'xss',
             'requires_validation': False,
             'tags': ['xss']}
        assert _is_url_pattern_candidate(m) is False

    def test_non_url_pattern_name_stays_finding(self):
        """Body-only patterns (debug-pages, etc.) never qualify as candidate
        even if source were mis-tagged."""
        m = {'source': 'url', 'pattern': 'debug-pages',
             'requires_validation': True}
        assert _is_url_pattern_candidate(m) is False

    def test_all_url_source_categories_route(self):
        for cat in URL_SOURCE_GF:
            m = {'source': 'url', 'pattern': cat,
                 'requires_validation': True, 'tags': [cat]}
            assert _is_url_pattern_candidate(m) is True, cat


class TestCandidateCategory:
    def test_strips_gf_prefix(self):
        m = {'pattern': 'gf:xss'}
        assert _candidate_category(m) == 'xss'

    def test_plain_name_passthrough(self):
        m = {'pattern': 'xss'}
        assert _candidate_category(m) == 'xss'


# ──────────────────────────────────────────────────────────────
# m14 — _read_candidates: preferred-source + fallback chain
# ──────────────────────────────────────────────────────────────

class TestM09CandidateReader:
    def test_reads_consolidated_json_when_present(self, tmp_path: Path):
        cand = [
            {'category': 'xss', 'url': 'https://x?q=1', 'match': '?q='},
            {'category': 'sqli', 'url': 'https://y?id=2', 'match': '?id=2'},
            {'category': 'xss', 'url': 'https://z?s=3', 'match': '?s='},
        ]
        (tmp_path / 'm14_candidates.json').write_text(json.dumps(cand))

        xss = _read_candidates(tmp_path, 'xss')
        assert set(xss) == {'https://x?q=1', 'https://z?s=3'}

        sqli = _read_candidates(tmp_path, 'sqli')
        assert sqli == ['https://y?id=2']

    def test_falls_back_to_gf_file_when_no_json(self, tmp_path: Path):
        (tmp_path / 'gf_xss.txt').write_text(
            'https://a?q=1\nhttps://b?s=2\n'
        )
        urls = _read_candidates(tmp_path, 'xss')
        assert set(urls) == {'https://a?q=1', 'https://b?s=2'}

    def test_merges_json_and_legacy_gf_file(self, tmp_path: Path):
        """If both files exist, JSON wins on order but legacy fills gaps."""
        (tmp_path / 'm14_candidates.json').write_text(json.dumps([
            {'category': 'xss', 'url': 'https://from-json?q=1'},
        ]))
        (tmp_path / 'gf_xss.txt').write_text(
            'https://from-json?q=1\nhttps://from-gf?q=2\n'
        )
        urls = _read_candidates(tmp_path, 'xss')
        # JSON entry first, then unique gf entry. No dupes.
        assert urls == ['https://from-json?q=1', 'https://from-gf?q=2']

    def test_returns_empty_when_no_files(self, tmp_path: Path):
        assert _read_candidates(tmp_path, 'xss') == []

    def test_unknown_category_returns_empty(self, tmp_path: Path):
        (tmp_path / 'm14_candidates.json').write_text(json.dumps([
            {'category': 'xss', 'url': 'https://x'},
        ]))
        assert _read_candidates(tmp_path, 'sqli') == []

    def test_malformed_json_falls_back_silently(self, tmp_path: Path):
        (tmp_path / 'm14_candidates.json').write_text('{broken json')
        (tmp_path / 'gf_xss.txt').write_text('https://from-gf?q=1\n')
        urls = _read_candidates(tmp_path, 'xss')
        assert urls == ['https://from-gf?q=1']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
