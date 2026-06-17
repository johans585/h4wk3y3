"""
Tests pour normalize_domain (parsing wildcards, URLs, etc.)
et la logique de routing single vs multi-target.
"""
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))



# Réplique la fonction comme définie dans h4wk3y3.py
def normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = d.removeprefix('http://').removeprefix('https://')
    d = d.rstrip('/')
    if d.startswith('*.'):
        d = d[2:]
    elif d.startswith('*'):
        d = d[1:]
    if d.startswith('.'):
        d = d[1:]
    return d


class TestNormalizeDomain:
    def test_wildcard_star_dot(self):
        assert normalize_domain('*.example.com') == 'example.com'

    def test_wildcard_star_only(self):
        assert normalize_domain('*example.com') == 'example.com'

    def test_leading_dot(self):
        assert normalize_domain('.example.com') == 'example.com'

    def test_http_prefix(self):
        assert normalize_domain('http://example.com') == 'example.com'

    def test_https_prefix(self):
        assert normalize_domain('https://example.com') == 'example.com'

    def test_https_with_path(self):
        assert normalize_domain('https://api.example.com/v1/') == 'api.example.com/v1'

    def test_trailing_slash(self):
        assert normalize_domain('example.com/') == 'example.com'

    def test_plain_domain(self):
        assert normalize_domain('example.com') == 'example.com'

    def test_subdomain_preserved(self):
        assert normalize_domain('api.example.com') == 'api.example.com'

    def test_uppercase_lowercased(self):
        assert normalize_domain('EXAMPLE.COM') == 'example.com'

    def test_whitespace_stripped(self):
        assert normalize_domain('  example.com  ') == 'example.com'

    def test_wildcard_with_subdomain(self):
        # *.sub.example.com -> sub.example.com
        assert normalize_domain('*.sub.example.com') == 'sub.example.com'

    def test_complex_scope_file(self):
        """Simule un fichier scope HackerOne typique."""
        scope_lines = [
            '*.example.com',
            '*.api.example.com',
            'https://admin.example.com/',
            'http://legacy.example.com',
            '.cdn.example.com',
            'example.com',
            '*.example.com',     # doublon
            'example.com',       # doublon
        ]
        normalized = list(dict.fromkeys(normalize_domain(l) for l in scope_lines))
        assert 'example.com' in normalized
        assert 'api.example.com' in normalized
        assert 'admin.example.com' in normalized
        assert 'legacy.example.com' in normalized
        assert 'cdn.example.com' in normalized
        # Doublons dédupliqués
        assert normalized.count('example.com') == 1


# TestRoutingLogic removed 2026-05-19 together with core/multi_pipeline.py:
# h4wk3y3.py now loops the single-target Pipeline over all domains, there is
# no longer a "single vs multi" routing decision to validate.
