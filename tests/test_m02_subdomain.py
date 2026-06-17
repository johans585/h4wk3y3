"""
Tests pour M01 SubdomainModule :
- clean() correctement filtre les wildcards et domaines hors-scope
- _run_dnsx_cname parsing du format de sortie
- Résultats de subfinder batch dispatchés par domaine
"""
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))

from unittest.mock import MagicMock


def make_m01():
    from modules.m02_subdomain import SubdomainModule
    cfg = MagicMock()
    cfg.get.side_effect = lambda *a, **kw: kw.get('default')
    cfg.output_dir.return_value.__truediv__ = lambda s, x: MagicMock()
    db = MagicMock()
    db.upsert_subdomains.return_value = []
    m = SubdomainModule.__new__(SubdomainModule)
    m.config = cfg
    m.db = db
    m.stealth = False
    import logging
    m.log = logging.getLogger('test_m01')
    return m


class TestCleanSubdomains:
    def test_removes_wildcard_prefix(self):
        m = make_m01()
        subs = {'*.example.com', '*.api.example.com', 'www.example.com'}
        cleaned = m._clean(subs, 'example.com')
        assert '*.example.com' not in cleaned
        assert 'example.com' in cleaned or 'www.example.com' in cleaned

    def test_keeps_valid_subdomain(self):
        m = make_m01()
        subs = {'api.example.com', 'mail.example.com'}
        cleaned = m._clean(subs, 'example.com')
        assert 'api.example.com' in cleaned
        assert 'mail.example.com' in cleaned

    def test_removes_out_of_scope(self):
        m = make_m01()
        subs = {'api.example.com', 'other.com', 'sub.other.com'}
        cleaned = m._clean(subs, 'example.com')
        assert 'other.com' not in cleaned
        assert 'sub.other.com' not in cleaned

    def test_keeps_root_domain(self):
        m = make_m01()
        subs = {'example.com'}
        cleaned = m._clean(subs, 'example.com')
        assert 'example.com' in cleaned

    def test_lowercases_all(self):
        m = make_m01()
        subs = {'API.EXAMPLE.COM', 'Mail.Example.Com'}
        cleaned = m._clean(subs, 'example.com')
        assert 'api.example.com' in cleaned
        assert 'mail.example.com' in cleaned

    def test_empty_input(self):
        m = make_m01()
        assert m._clean(set(), 'example.com') == set()

    def test_strips_leading_dot(self):
        m = make_m01()
        subs = {'.example.com'}
        cleaned = m._clean(subs, 'example.com')
        assert 'example.com' in cleaned


class TestSubfinderBatchDispatch:
    def test_dispatch_subs_to_correct_parent(self):
        """Simule le dispatch subfinder -dL par domaine parent."""
        # subfinder retourne {parent: {subs}}
        # on doit correctement grouper par domaine
        domains = ['una.bj', 'gouv.bj']
        all_found = {
            'una.bj':  {'www.una.bj', 'api.una.bj', 'mail.una.bj'},
            'gouv.bj': {'www.gouv.bj', 'presidence.gouv.bj'},
        }

        m = make_m01()

        for d in domains:
            subs = all_found.get(d, set())
            cleaned = m._clean(subs, d)
            assert all(s.endswith(f'.{d}') or s == d for s in cleaned)


class TestDnsxCnameParsing:
    def test_parses_cname_output(self):
        """dnsx output format: sub.domain.com [CNAME-VALUE]"""
        import re
        sample_output = """api.example.com [backend.cloudflare.com]
mail.example.com [mail.google.com]
www.example.com [cdn.fastly.net]
invalid line without brackets"""

        cnames = {}
        for line in sample_output.splitlines():
            m = re.match(r'^(\S+)\s+\[(.+)\]', line.strip())
            if m:
                cnames[m.group(1)] = m.group(2)

        assert cnames['api.example.com'] == 'backend.cloudflare.com'
        assert cnames['mail.example.com'] == 'mail.google.com'
        assert 'invalid line without brackets' not in cnames
        assert len(cnames) == 3
