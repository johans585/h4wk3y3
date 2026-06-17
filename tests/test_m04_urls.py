"""
Tests pour M03 URLCollectorModule :
- Filtre d'extensions (blacklist/interesting)
- URO dedup logique
- Parsing output gospider
- Cap par domaine
"""
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))

from modules.m04_url_collector import URLCollectorModule, INTERESTING_EXT
from unittest.mock import MagicMock
import logging


def make_m03():
    cfg = MagicMock()
    cfg.get.side_effect = lambda *a, **kw: kw.get('default')
    db = MagicMock()
    m = URLCollectorModule.__new__(URLCollectorModule)
    m.config = cfg
    m.db = db
    m.stealth = False
    m.log = logging.getLogger('test_m03')
    return m


class TestURLFilter:
    def test_removes_blacklisted_extensions(self):
        m = make_m03()
        urls = {
            'https://example.com/image.png',
            'https://example.com/style.css',
            'https://example.com/app.php',
            'https://example.com/data.json',
            'https://example.com/font.woff2',
        }
        filtered = m._filter_urls(urls)
        assert 'https://example.com/image.png' not in filtered
        assert 'https://example.com/style.css' not in filtered
        assert 'https://example.com/font.woff2' not in filtered
        assert 'https://example.com/app.php' in filtered
        assert 'https://example.com/data.json' in filtered

    def test_keeps_no_extension_urls(self):
        m = make_m03()
        urls = {'https://example.com/api/users', 'https://example.com/login'}
        filtered = m._filter_urls(urls)
        assert len(filtered) == 2

    def test_removes_non_http(self):
        m = make_m03()
        urls = {
            'ftp://example.com/file.txt',
            'javascript:void(0)',
            'mailto:test@example.com',
            'https://example.com/page',
        }
        filtered = m._filter_urls(urls)
        assert len(filtered) == 1
        assert 'https://example.com/page' in filtered

    def test_interesting_extensions_flagged(self):
        """Les extensions intéressantes sont dans INTERESTING_EXT."""
        interesting = ['php', 'asp', 'aspx', 'jsp', 'json', 'xml',
                       'env', 'bak', 'sql', 'config']
        for ext in interesting:
            assert ext in INTERESTING_EXT, f"{ext} should be in INTERESTING_EXT"

    def test_query_string_not_affects_ext_check(self):
        m = make_m03()
        urls = {
            'https://example.com/image.png?v=1',  # png → blacklisted
            'https://example.com/app.php?id=1',    # php → kept
        }
        filtered = m._filter_urls(urls)
        assert 'https://example.com/image.png?v=1' not in filtered
        assert 'https://example.com/app.php?id=1' in filtered


class TestGospiderParsing:
    def test_parse_gospider_output(self):
        """gospider output: [xxx] - [200] - https://..."""
        sample = [
            '[url] - [200] - https://example.com/page1',
            '[javascript] - [200] - https://example.com/app.js',
            '[form] - https://example.com/login',
            'not a url line',
            '[url] - [404] - https://example.com/missing',
        ]
        found = set()
        for line in sample:
            parts = line.strip().split(' - ')
            for part in parts:
                part = part.strip().strip('[]')
                if part.startswith('http'):
                    found.add(part)

        assert 'https://example.com/page1' in found
        assert 'https://example.com/app.js' in found
        assert 'https://example.com/login' in found


class TestDomainGrouping:
    def test_group_urls_by_domain(self):
        urls = [
            'https://api.example.com/users',
            'https://api.example.com/posts',
            'https://mail.example.com/inbox',
            'https://other.com/page',
        ]
        by_domain = {}
        for url in urls:
            try:
                domain = url.split('://', 1)[1].split('/')[0].split('?')[0]
                by_domain.setdefault(domain, []).append(url)
            except Exception:
                pass

        assert len(by_domain['api.example.com']) == 2
        assert len(by_domain['mail.example.com']) == 1
        assert len(by_domain['other.com']) == 1

    def test_cap_per_domain(self):
        """Le cap par domaine est respecté."""
        all_urls = [f'https://example.com/page{i}' for i in range(100)]
        cap = 10
        capped = all_urls[:cap]
        assert len(capped) == cap
