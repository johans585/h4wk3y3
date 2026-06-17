"""
Tests pour le backend FastAPI (dashboard) :
- Routes GET principales
- DELETE domain
- Graceful 404/empty sur données manquantes
- Format des réponses
"""
import sys
import os
import json
import io
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))

# TestClient talks to the app over plain HTTP; the session cookie is set Secure
# by default and would not be sent back. DASHBOARD_HTTP_DEV=1 disables the
# Secure attribute so the cookie round-trips during tests.
os.environ.setdefault('DASHBOARD_HTTP_DEV', '1')

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from core.config import ArgusConfig
from tests.conftest import _read_bootstrap_pw
from dashboard.backend.app import create_app


@pytest.fixture
def client(tmp_path, db):
    """FastAPI test client backed by the Postgres `db` fixture from conftest.

    The fixture also creates a per-test ``output/`` dir under tmp_path so
    the dashboard can serve scan results from there without trashing the
    real ``./output/`` directory.
    """
    tmp_out = str(tmp_path / 'output')
    Path(tmp_out).mkdir()

    cfg = ArgusConfig()
    cfg._data.setdefault('general', {})['output_dir'] = tmp_out

    # The bootstrap password is intentionally NOT printed (it would leak to
    # logs); create_app() prints only the path to the 0600 creds file. We
    # parse that path from stdout and read the password from the file.
    buf = io.StringIO()
    _stdout = sys.stdout
    sys.stdout = buf
    try:
        app = create_app(cfg, db)
    finally:
        sys.stdout = _stdout
    bootstrap_pw = _read_bootstrap_pw(buf.getvalue())
    client = TestClient(app)
    if bootstrap_pw:
        r = client.post('/api/auth/login',
                        data={'username': 'admin', 'password': bootstrap_pw})
        assert r.status_code == 200, f"bootstrap login failed: {r.status_code} {r.text}"
        # CSRF (Étape 1.5) — server returns the token in the login response.
        # Patch TestClient.request so every mutating call carries X-CSRF-Token
        # without forcing every test to thread the token by hand.
        csrf_token = r.json().get('csrf_token')
        assert csrf_token, "login response missing csrf_token"
        _orig_request = client.request
        def _request_with_csrf(method, url, **kw):
            if method.upper() in ('POST', 'PUT', 'DELETE', 'PATCH'):
                headers = dict(kw.pop('headers', {}) or {})
                headers.setdefault('X-CSRF-Token', csrf_token)
                kw['headers'] = headers
            return _orig_request(method, url, **kw)
        client.request = _request_with_csrf

    # Crée un domaine de test avec des données
    domain = 'test.example.com'
    domain_dir = Path(tmp_out) / domain
    domain_dir.mkdir()

    # Données minimales
    (domain_dir / 'scan_summary.json').write_text(json.dumps({
        'scan_id': 'abc123', 'domain': domain, 'subdomains': 5,
        'live_hosts': 2, 'urls': 100, 'findings': 10,
        'by_severity': {'critical':1,'high':2,'medium':3,'low':4,'info':0},
        'started_at': '2026-01-01T00:00:00', 'finished_at': '2026-01-01T01:00:00'
    }))
    (domain_dir / 'subdomains.txt').write_text('api.test.example.com\nmail.test.example.com\n')
    (domain_dir / 'live_hosts.json').write_text(json.dumps([
        {'url':'https://api.test.example.com','domain':'api.test.example.com',
         'status_code':200,'title':'API','technologies':['Nginx'],'confidence':0.9}
    ]))
    (domain_dir / 'tech_report.json').write_text(json.dumps(
        {'https://api.test.example.com': ['Nginx']}
    ))
    (domain_dir / 'urls_all.txt').write_text(
        'https://api.test.example.com/users\nhttps://api.test.example.com/posts\n'
    )
    (domain_dir / 'js_secrets.json').write_text('[]')
    (domain_dir / 'js_endpoints.json').write_text('[]')
    (domain_dir / 'takeovers.json').write_text('[]')
    (domain_dir / 'patterns.json').write_text('[]')
    (domain_dir / 'fetch_results.json').write_text('[]')
    (domain_dir / 'bodies_snippets.json').write_text('{}')
    (domain_dir / 'headers.json').write_text('{}')

    # DB seed (canonical source post-2026-05). Each finding has a distinct
    # url so the fingerprint dedup doesn't collapse them into one row.
    import time as _time
    from core.models import Finding, FindingType, Severity

    # Previous scan first — older started_at lets diff_findings consider
    # scan abc123 as the most-recent one.
    db.create_scan('prev-scan', domain)
    db.finish_scan('prev-scan', {
        'subdomains': 4, 'live_hosts': 1, 'findings': 5,
        'by_severity': {'critical': 0, 'high': 1, 'medium': 3, 'low': 1, 'info': 0},
    })
    _time.sleep(0.02)

    db.create_scan('abc123', domain)
    db.upsert_subdomains('abc123', domain,
                         ['api.test.example.com', 'mail.test.example.com'])
    db.upsert_live_hosts('abc123', domain, [
        {'url': 'https://api.test.example.com',
         'domain': 'api.test.example.com',
         'status_code': 200, 'title': 'API',
         'technologies': ['Nginx']},
    ])
    for i, sev in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]):
        f = Finding(type=FindingType.PATTERN_MATCH, target=domain,
                    title=f'Test {sev.value}', severity=sev, confidence=0.8,
                    url=f'https://api.test.example.com/issue-{i}',
                    scan_id='abc123')
        db.save_finding(f, domain)
    db.finish_scan('abc123', {
        'subdomains': 2, 'live_hosts': 1, 'findings': 3,
        'by_severity': {'critical': 1, 'high': 1, 'medium': 1, 'low': 0, 'info': 0},
    })

    # 4th element kept for back-compat with tests that unpack 4 values
    # (e.g. ``c, domain, tmp_out, db_path = client``). It used to be the
    # SQLite file path; with Postgres we expose the live ``db`` object
    # instead so tests can re-query the DB directly.
    yield client, domain, tmp_out, db

    # `db` close + truncate handled by the conftest `db` fixture.


class TestDomainRoutes:
    def test_list_domains(self, client):
        c, domain, *_ = client
        r = c.get('/api/domains')
        assert r.status_code == 200
        data = r.json()
        assert any(d['domain'] == domain for d in data)

    def test_get_summary(self, client):
        c, domain, *_ = client
        r = c.get(f'/api/summary/{domain}')
        assert r.status_code == 200
        data = r.json()
        assert data['domain'] == domain
        assert data['by_severity']['critical'] == 1

    def test_get_summary_404(self, client):
        c, *_ = client
        r = c.get('/api/summary/nonexistent.com')
        assert r.status_code == 404

    def test_get_subdomains(self, client):
        c, domain, *_ = client
        r = c.get(f'/api/subdomains/{domain}')
        assert r.status_code == 200
        data = r.json()
        assert data['count'] == 2
        assert 'api.test.example.com' in data['subdomains']

    def test_get_live_hosts(self, client):
        c, domain, *_ = client
        r = c.get(f'/api/live-hosts-full/{domain}')
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]['technologies'] == ['Nginx']

    def test_get_tech(self, client):
        c, domain, *_ = client
        r = c.get(f'/api/tech/{domain}')
        assert r.status_code == 200
        data = r.json()
        assert 'https://api.test.example.com' in data

    def test_get_urls(self, client):
        c, domain, *_ = client
        r = c.get(f'/api/urls/{domain}')
        assert r.status_code == 200
        data = r.json()
        assert data['count'] == 2
        assert len(data['urls']) == 2

    def test_get_findings_filter_severity(self, client):
        c, domain, *_ = client
        r = c.get(f'/api/findings?domain={domain}&severity=critical')
        assert r.status_code == 200
        data = r.json()
        assert all(f['severity'] == 'critical' for f in data)

    def test_get_js_secrets_empty(self, client):
        c, domain, *_ = client
        r = c.get(f'/api/js-secrets/{domain}')
        assert r.status_code == 200
        assert r.json() == []

    def test_get_bodies_snippets(self, client):
        c, domain, *_ = client
        r = c.get(f'/api/bodies-snippets/{domain}')
        assert r.status_code == 200
        # Retourne {} si vide, pas 404
        assert r.json() == {}

    def test_get_bodies_snippets_missing_domain(self, client):
        c, *_ = client
        r = c.get('/api/bodies-snippets/missing.com')
        assert r.status_code == 200  # graceful, retourne {}
        assert r.json() == {}

    def test_gf_categories_empty(self, client):
        c, domain, *_ = client
        r = c.get(f'/api/gf/{domain}')
        assert r.status_code == 200
        assert r.json() == []

    def test_gf_results_missing_category(self, client):
        c, domain, *_ = client
        r = c.get(f'/api/gf/{domain}/xss')
        assert r.status_code == 200
        data = r.json()
        assert data['count'] == 0
        assert data['urls'] == []


class TestDeleteDomain:
    def test_delete_removes_output_dir(self, client):
        c, domain, tmp_out, *_ = client
        domain_dir = Path(tmp_out) / domain
        assert domain_dir.exists()

        r = c.delete(f'/api/domains/{domain}')
        assert r.status_code == 200
        assert r.json()['ok'] is True
        assert not domain_dir.exists()

    def test_delete_removes_from_db(self, client):
        # 4th element is the live ArgusDB (Postgres-backed) since the
        # SQLite path tuple was retired in the PG-only switch.
        c, domain, _, db = client
        # Before delete
        assert len(db.get_subdomains(domain)) > 0

        c.delete(f'/api/domains/{domain}')

        assert len(db.get_subdomains(domain)) == 0
        assert len(db.get_findings(domain=domain)) == 0

    def test_delete_nonexistent_domain_no_crash(self, client):
        c, *_ = client
        r = c.delete('/api/domains/nonexistent.com')
        assert r.status_code == 200
        assert r.json()['ok'] is True


class TestPrevSummary:
    """``prev_summary`` now comes from the DB (Étape DB-canonical 2026-05).

    The fixture seeds 2 scans (prev-scan + abc123) so the latest one has a
    predecessor — that's the happy path. The first-scan-only case uses a
    fresh client + a single-scan setup."""

    def test_prev_summary_included_when_two_scans(self, client):
        c, domain, *_ = client
        r = c.get(f'/api/summary/{domain}')
        data = r.json()
        assert 'prev_summary' in data
        assert data['prev_summary']['findings'] == 5
        assert data['prev_summary']['scan_id'] == 'prev-scan'

    def test_no_prev_summary_when_first_scan(self, client, db):
        """Wipe the prev-scan row out of DB so abc123 is the only scan."""
        import sqlalchemy as sa
        from core import orm
        c, domain, *_ = client
        with db.engine.begin() as conn:
            conn.execute(sa.delete(orm.Scan.__table__).where(
                orm.Scan.__table__.c.scan_id == 'prev-scan'))
        r = c.get(f'/api/summary/{domain}')
        data = r.json()
        assert 'prev_summary' not in data


class TestDiffEndpoint:
    """Étape 1.2 — /api/diff/{domain} returns new + gone vs previous scan."""

    def test_diff_first_scan_all_new(self, client):
        c, domain, *_ = client
        # Fixture seeds 2 scans (prev-scan + abc123). The diff endpoint
        # returns ``new`` = findings first observed in abc123 (the seed
        # plants 3 of them) and ``gone`` = findings last seen in prev-scan
        # but not in abc123 (none seeded → empty).
        r = c.get(f'/api/diff/{domain}')
        assert r.status_code == 200
        body = r.json()
        assert body['domain'] == domain
        assert body['current_scan_id'] == 'abc123'
        assert body['since_scan_id'] == 'prev-scan'
        assert isinstance(body['new'], list)
        assert isinstance(body['gone'], list)
        assert len(body['new']) >= 1
        assert body['gone'] == []

    def test_diff_invalid_domain_rejected(self, client):
        c, *_ = client
        r = c.get('/api/diff/../etc/passwd')
        # FastAPI rewrites the slash, but the validator must still reject.
        assert r.status_code in (400, 404)

    def test_diff_unknown_domain_404(self, client):
        c, *_ = client
        r = c.get('/api/diff/never-scanned.com')
        assert r.status_code == 404


# ─────────────────────────────────────────────────────────────────────
# Multi-org (Étape 2.1) — /api/orgs/* + filtre ?org=
# ─────────────────────────────────────────────────────────────────────

class TestOrgsEndpoints:
    def test_list_empty(self, client):
        c, *_ = client
        r = c.get('/api/orgs')
        assert r.status_code == 200
        assert r.json() == []

    def test_create_then_list(self, client):
        c, *_ = client
        r = c.post('/api/orgs', json={'name': 'acme', 'h1_handle': 'acme'})
        assert r.status_code == 200, r.text
        assert r.json()['name'] == 'acme'
        r = c.get('/api/orgs')
        assert r.status_code == 200
        names = [o['name'] for o in r.json()]
        assert 'acme' in names
        # target_count enrichment
        assert r.json()[0]['target_count'] == 0

    def test_create_requires_name(self, client):
        c, *_ = client
        r = c.post('/api/orgs', json={'h1_handle': 'x'})
        assert r.status_code == 400

    def test_create_duplicate_returns_400(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'acme'})
        r = c.post('/api/orgs', json={'name': 'acme'})
        assert r.status_code == 400

    def test_show_404(self, client):
        c, *_ = client
        r = c.get('/api/orgs/ghost')
        assert r.status_code == 404

    def test_show_returns_targets_and_stats(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'acme'})
        c.post('/api/orgs/acme/targets', json={'apex': 'acme.com'})
        r = c.get('/api/orgs/acme')
        assert r.status_code == 200
        body = r.json()
        assert body['organisation']['name'] == 'acme'
        apexes = [t['apex'] for t in body['targets']]
        assert 'acme.com' in apexes
        assert body['stats']['exists'] is True
        assert body['stats']['targets'] == 1

    def test_patch_update(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'acme'})
        r = c.patch('/api/orgs/acme', json={'h1_handle': 'acme-h1'})
        assert r.status_code == 200, r.text
        assert r.json()['h1_handle'] == 'acme-h1'

    def test_patch_empty_payload_400(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'acme'})
        r = c.patch('/api/orgs/acme', json={})
        assert r.status_code == 400

    def test_patch_clear(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'acme', 'h1_handle': 'acme'})
        r = c.patch('/api/orgs/acme', json={'h1_handle': None})
        assert r.status_code == 200
        assert r.json()['h1_handle'] is None

    def test_link_target(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'acme'})
        r = c.post('/api/orgs/acme/targets', json={'apex': 'acme.com'})
        assert r.status_code == 200
        assert r.json()['apex'] == 'acme.com'

    def test_link_target_unknown_org(self, client):
        c, *_ = client
        r = c.post('/api/orgs/ghost/targets', json={'apex': 'x.com'})
        assert r.status_code == 404

    def test_unlink_target_404_when_not_linked_here(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'acme'})
        c.post('/api/orgs', json={'name': 'wonka'})
        c.post('/api/orgs/acme/targets', json={'apex': 'acme.com'})
        # acme.com belongs to acme, not wonka — must 404
        r = c.delete('/api/orgs/wonka/targets/acme.com')
        assert r.status_code == 404

    def test_unlink_target_happy(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'acme'})
        c.post('/api/orgs/acme/targets', json={'apex': 'acme.com'})
        r = c.delete('/api/orgs/acme/targets/acme.com')
        assert r.status_code == 200
        # After unlink, the target row exists in the unlinked listing
        r = c.get('/api/targets?unlinked=true')
        assert r.status_code == 200
        apexes = [t['apex'] for t in r.json()]
        assert 'acme.com' in apexes

    def test_delete_refused_when_targets(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'acme'})
        c.post('/api/orgs/acme/targets', json={'apex': 'acme.com'})
        r = c.delete('/api/orgs/acme')
        assert r.status_code == 409
        # Force succeeds
        r = c.delete('/api/orgs/acme?force=true')
        assert r.status_code == 200

    def test_stats_404_for_unknown_org(self, client):
        c, *_ = client
        r = c.get('/api/orgs/ghost/stats')
        assert r.status_code == 404

    def test_targets_list_all(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'acme'})
        c.post('/api/orgs/acme/targets', json={'apex': 'acme.com'})
        c.post('/api/orgs/acme/targets', json={'apex': 'api.acme.io'})
        r = c.get('/api/targets')
        assert r.status_code == 200
        apexes = [t['apex'] for t in r.json()]
        assert {'acme.com', 'api.acme.io'} <= set(apexes)

    def test_targets_filtered_by_org(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'acme'})
        c.post('/api/orgs', json={'name': 'wonka'})
        c.post('/api/orgs/acme/targets', json={'apex': 'acme.com'})
        c.post('/api/orgs/wonka/targets', json={'apex': 'wonka.com'})
        r = c.get('/api/targets?org=acme')
        apexes = [t['apex'] for t in r.json()]
        assert apexes == ['acme.com']


class TestOrgFindingsFilter:
    """Filter ?org=<name> applied on /api/findings + /api/findings/stats."""

    def test_findings_filter_by_org(self, client):
        c, domain, *_ = client
        # Link the seed domain to an org so it appears under the filter
        c.post('/api/orgs', json={'name': 'seed-org'})
        c.post('/api/orgs/seed-org/targets', json={'apex': domain})
        r = c.get('/api/findings?org=seed-org&limit=100')
        assert r.status_code == 200
        rows = r.json()
        # Seeded fixture has 3 findings on `domain`
        assert len(rows) >= 1
        assert all(row['domain'] == domain for row in rows)

    def test_findings_filter_unknown_org_404(self, client):
        c, *_ = client
        r = c.get('/api/findings?org=ghost')
        assert r.status_code == 404

    def test_findings_filter_org_with_no_targets_empty(self, client):
        c, *_ = client
        c.post('/api/orgs', json={'name': 'empty-org'})
        r = c.get('/api/findings?org=empty-org')
        assert r.status_code == 200
        assert r.json() == []

    def test_findings_stats_filter_by_org(self, client):
        c, domain, *_ = client
        c.post('/api/orgs', json={'name': 'seed-org'})
        c.post('/api/orgs/seed-org/targets', json={'apex': domain})
        r = c.get('/api/findings/stats?org=seed-org')
        assert r.status_code == 200
        assert domain in r.json()

    def test_findings_filter_org_domain_intersection_empty(self, client):
        c, *_ = client
        # Domain is not in the org → empty result, no error
        c.post('/api/orgs', json={'name': 'isolated'})
        r = c.get('/api/findings?org=isolated&domain=anything.com')
        assert r.status_code == 200
        assert r.json() == []
