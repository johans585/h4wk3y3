"""Unit tests for M10 Fast Fetcher — network-error taxonomy + pure helpers.

No real network, no sockets. The error taxonomy lives in the `_attempt`
closure of `run()`; we assert its shape against the module source via AST
(load-bearing: the retry path keys off `_kind in ('timeout','dns','reset')`),
and we exercise the deterministic pieces the module actually relies on
(shared INTERESTING_EXT extension filter, extension extraction, title regex,
dedup, error Counter).
"""
import ast
import re
import sys
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import aiohttp
import pytest

import modules.m10_fetcher as fetcher
from modules.m04_url_collector import INTERESTING_EXT


_SRC = Path(fetcher.__file__).read_text()


def _attempt_handlers():
    """Extract the (exception-type-names, _kind) pairs from the `_attempt`
    closure's except clauses, in source order."""
    tree = ast.parse(_SRC)
    handlers = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == '_attempt':
            for h in ast.walk(node):
                if isinstance(h, ast.ExceptHandler):
                    # collect exception type names
                    names = []
                    et = h.type
                    parts = et.elts if isinstance(et, ast.Tuple) else ([et] if et else [])
                    for p in parts:
                        names.append(ast.unparse(p))
                    # find the _kind string literal assigned in this handler
                    kind = None
                    for sub in ast.walk(h):
                        if (isinstance(sub, ast.Dict)):
                            for k, v in zip(sub.keys, sub.values):
                                if (isinstance(k, ast.Constant) and k.value == '_kind'
                                        and isinstance(v, ast.Constant)):
                                    kind = v.value
                    handlers.append((names, kind))
    return handlers


class TestErrorTaxonomy:
    def test_attempt_closure_exists(self):
        assert any(
            isinstance(n, ast.AsyncFunctionDef) and n.name == '_attempt'
            for n in ast.walk(ast.parse(_SRC))
        )

    def test_all_transport_kinds_present(self):
        kinds = {k for _, k in _attempt_handlers()}
        assert {'timeout', 'dns', 'reset', 'ssl', 'other'} <= kinds

    def test_timeout_mapped_to_asyncio_timeouterror(self):
        h = _attempt_handlers()
        types_for_timeout = next(names for names, k in h if k == 'timeout')
        assert any('TimeoutError' in n for n in types_for_timeout)

    def test_dns_mapped_to_dns_error(self):
        h = _attempt_handlers()
        types = next(names for names, k in h if k == 'dns')
        assert any('ClientConnectorDNSError' in n for n in types)

    def test_reset_covers_disconnect_and_oserror(self):
        h = _attempt_handlers()
        types = next(names for names, k in h if k == 'reset')
        joined = ' '.join(types)
        assert 'ServerDisconnectedError' in joined and 'ClientOSError' in joined

    def test_ssl_mapped_to_clientsslerror(self):
        h = _attempt_handlers()
        types = next(names for names, k in h if k == 'ssl')
        assert any('ClientSSLError' in n for n in types)

    def test_other_is_bare_exception_catchall(self):
        h = _attempt_handlers()
        types = next(names for names, k in h if k == 'other')
        assert types == ['Exception']

    def test_other_handler_is_last(self):
        # The broad Exception catch-all must come last, otherwise it would
        # shadow the specific transport classes.
        h = _attempt_handlers()
        assert h[-1][1] == 'other'

    def test_referenced_exceptions_actually_exist(self):
        # The specific aiohttp exception classes the taxonomy names must be
        # real attributes of the installed aiohttp (no typos / API drift).
        assert issubclass(aiohttp.ClientConnectorDNSError, Exception)
        assert issubclass(aiohttp.ClientSSLError, Exception)
        assert issubclass(aiohttp.ServerDisconnectedError, Exception)
        assert issubclass(aiohttp.ClientOSError, Exception)


class TestRetryPredicate:
    """run() retries once only on transient kinds, never on ssl/other."""
    RETRYABLE = ('timeout', 'dns', 'reset')

    @staticmethod
    def _should_retry(status, kind):
        return status == 0 and kind in ('timeout', 'dns', 'reset')

    def test_transient_kinds_retry(self):
        for k in self.RETRYABLE:
            assert self._should_retry(0, k) is True

    def test_ssl_not_retried(self):
        assert self._should_retry(0, 'ssl') is False

    def test_other_not_retried(self):
        assert self._should_retry(0, 'other') is False

    def test_success_status_not_retried(self):
        assert self._should_retry(200, 'timeout') is False

    def test_source_uses_exact_transient_set(self):
        # Guard the predicate's literal tuple against silent edits.
        assert "('timeout', 'dns', 'reset')" in _SRC


class TestExtensionFilter:
    """run() keeps a URL if it has no extension OR ext in INTERESTING_EXT."""
    @staticmethod
    def _ext(u):
        path = u.split('?')[0]
        return path.rsplit('.', 1)[-1].lower() if '.' in path.split('/')[-1] else ''

    @staticmethod
    def _keep(u):
        ext = TestExtensionFilter._ext(u)
        return not ext or ext in INTERESTING_EXT

    def test_no_extension_kept(self):
        assert self._keep('https://t.io/api/users')

    def test_trailing_slash_has_no_ext_kept(self):
        assert self._keep('https://t.io/admin/')

    def test_php_kept(self):
        assert self._ext('https://t.io/index.php') == 'php'
        assert self._keep('https://t.io/index.php')

    def test_env_kept(self):
        assert self._keep('https://t.io/.env')

    def test_png_dropped(self):
        assert self._ext('https://t.io/logo.png') == 'png'
        assert self._keep('https://t.io/logo.png') is False

    def test_query_string_ignored_for_ext(self):
        # dot in query must not be treated as the path extension
        assert self._ext('https://t.io/page?next=a.b.png') == ''
        assert self._keep('https://t.io/page?next=a.b.png')

    def test_dot_in_path_segment_not_filename(self):
        # last segment has no dot → no extension
        assert self._ext('https://t.io/v1.2/users') == ''

    def test_interesting_ext_is_shared_set(self):
        assert isinstance(INTERESTING_EXT, set)
        assert {'php', 'env', 'sql', 'bak'} <= INTERESTING_EXT


class TestDedupOrder:
    def test_dict_fromkeys_dedups_preserving_order(self):
        sources = ['https://a', 'https://b']
        extra = ['https://b', 'https://c', 'https://a']
        out = list(dict.fromkeys(sources + extra))
        assert out == ['https://a', 'https://b', 'https://c']


class TestTitleRegex:
    PAT = re.compile(r'<title[^>]*>([^<]{0,200})</title>', re.I)

    def test_extracts_title(self):
        m = self.PAT.search("<html><title>Hello World</title></html>")
        assert m.group(1) == 'Hello World'

    def test_case_insensitive_and_attrs(self):
        m = self.PAT.search('<TITLE lang="en">Admin</TITLE>')
        assert m.group(1) == 'Admin'

    def test_no_title_returns_none(self):
        assert self.PAT.search("<html><body>no title</body></html>") is None

    def test_title_pattern_present_in_source(self):
        assert r'<title[^>]*>([^<]{0,200})</title>' in _SRC


class TestErrorCounter:
    def test_error_breakdown_counts_by_kind(self):
        errors = [
            {'error': 'timeout'}, {'error': 'timeout'},
            {'error': 'dns'}, {'error': 'other'},
        ]
        dist = Counter(r.get('error', 'other') for r in errors)
        assert dist['timeout'] == 2
        assert dist['dns'] == 1
        assert dist['other'] == 1

    def test_missing_error_key_defaults_other(self):
        dist = Counter(r.get('error', 'other') for r in [{}])
        assert dist['other'] == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
