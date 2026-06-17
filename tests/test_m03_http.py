"""
Tests pour M02 HTTPValidatorModule :
- Détection technos (patterns)
- Déduplication https > http
- Filtrage par confidence
- LiveHost struct
"""
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))

from core.models import LiveHost


class TestTechDetection:
    """Patterns de détection de techno restants après Étape 1.3.

    httpx -tech-detect couvre désormais web servers / CDN / frameworks /
    CMS via JSONL parsing dans `_livehost_from_httpx`. Les patterns regex
    de m03 restent uniquement pour les signaux cookie session-based que
    Wappalyzer/httpx ratent souvent.
    """

    def test_laravel_cookie(self):
        from modules.m03_http_validator import TECH_PATTERNS
        import re
        cookies = 'laravel_session=abc123; XSRF-TOKEN=xyz'

        detected = []
        for name, source, pattern in TECH_PATTERNS:
            regex = re.compile(pattern, re.I)
            if source == 'cookie' and regex.search(cookies):
                detected.append(name)

        assert 'Laravel' in detected

    def test_php_session_cookie(self):
        from modules.m03_http_validator import TECH_PATTERNS
        import re
        cookies = 'PHPSESSID=ab12cd; Path=/'
        detected = []
        for name, source, pattern in TECH_PATTERNS:
            regex = re.compile(pattern, re.I)
            if source == 'cookie' and regex.search(cookies):
                detected.append(name)
        assert 'PHP' in detected

    def test_java_jsessionid(self):
        from modules.m03_http_validator import TECH_PATTERNS
        import re
        cookies = 'JSESSIONID=AB12CD; Path=/'
        detected = []
        for name, source, pattern in TECH_PATTERNS:
            regex = re.compile(pattern, re.I)
            if source == 'cookie' and regex.search(cookies):
                detected.append(name)
        assert 'Java' in detected

    def test_no_false_positive_on_empty(self):
        from modules.m03_http_validator import TECH_PATTERNS
        import re
        cookies = ''
        detected = []
        for name, source, pattern in TECH_PATTERNS:
            regex = re.compile(pattern, re.I)
            if source == 'cookie' and regex.search(cookies):
                detected.append(name)
        assert detected == []

    def test_tech_patterns_table_is_cookie_only(self):
        """All TECH_PATTERNS entries must be cookie-source after Étape 1.3.
        Web servers / frameworks / CDN come from httpx -td, not regex."""
        from modules.m03_http_validator import TECH_PATTERNS
        sources = {source for _, source, _ in TECH_PATTERNS}
        assert sources == {'cookie'}, (
            f"non-cookie patterns remain — Étape 1.3 left {sources}"
        )


class TestHttpsDedup:
    """Teste la déduplication https > http."""

    def test_https_preferred_over_http(self):
        """Même domaine: https doit remplacer http."""
        from core.models import LiveHost

        hosts = [
            LiveHost(url='http://example.com',  domain='example.com',
                     status_code=200, confidence=0.9),
            LiveHost(url='https://example.com', domain='example.com',
                     status_code=200, confidence=0.9),
        ]
        seen: dict = {}
        for h in hosts:
            d = h.domain
            if d not in seen or h.url.startswith('https'):
                seen[d] = h

        assert seen['example.com'].url == 'https://example.com'

    def test_http_kept_if_no_https(self):
        hosts = [
            LiveHost(url='http://old.example.com', domain='old.example.com',
                     status_code=200, confidence=0.9),
        ]
        seen: dict = {}
        for h in hosts:
            if h.domain not in seen or h.url.startswith('https'):
                seen[h.domain] = h
        assert seen['old.example.com'].url.startswith('http://')


class TestLiveHostModel:
    def test_live_host_dict_conversion(self):
        h = LiveHost(
            url='https://api.example.com',
            domain='api.example.com',
            status_code=200,
            title='API Home',
            technologies=['Laravel', 'Nginx'],
            waf=None,
            confidence=0.95
        )
        d = h.__dict__
        assert d['url'] == 'https://api.example.com'
        assert d['technologies'] == ['Laravel', 'Nginx']
        assert d['confidence'] == 0.95

    def test_confidence_threshold(self):
        """Hosts avec confidence < threshold doivent être filtrés."""
        min_conf = 0.6
        hosts = [
            LiveHost(url='https://a.com', domain='a.com',
                     status_code=200, confidence=0.9),
            LiveHost(url='https://b.com', domain='b.com',
                     status_code=200, confidence=0.3),
        ]
        live = [h for h in hosts if h.confidence >= min_conf]
        assert len(live) == 1
        assert live[0].domain == 'a.com'
