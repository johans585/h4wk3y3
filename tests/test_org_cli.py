"""Tests for `argus org ...` CLI subcommand (Étape 2.1 multi-org).

Driven via subprocess so argparse wiring in h4wk3y3.py is also covered.
The CLI hits the live argus_main DB (same as `argus org` in production),
so each test cleans up after itself.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
ARGUS_PY = REPO / "h4wk3y3.py"


def _run(*args, env_extra=None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    # Point the CLI subprocess at the SAME DB the `db` fixture uses (resolve_db_url
    # honours ARGUS_DB_URL first), so org-CLI tests don't leak cli-* rows into the
    # production DB (argus_main). When no test DB is configured the fixture skips,
    # so this is a no-op there.
    test_url = os.environ.get("ARGUS_TEST_POSTGRES_URL")
    if test_url:
        env.setdefault("ARGUS_DB_URL", test_url)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(ARGUS_PY), "org", *args],
        capture_output=True, text=True, env=env, cwd=REPO,
    )


@pytest.fixture
def org_name(db):
    """Unique org name per test so we don't collide if tests run in parallel."""
    # `db` from conftest also TRUNCATEs the org tables, but we still pick a
    # unique-ish name as defence in depth.
    yield "cli-" + uuid.uuid4().hex[:8]


class TestOrgCli:
    def test_list_empty(self, org_name, db):
        r = _run("list")
        assert r.returncode == 0, r.stderr
        assert "(no rows)" in r.stdout or "name" in r.stdout

    def test_add_then_list(self, org_name, db):
        r = _run("add", org_name, "--h1", "h1-handle",
                 "--scope-file", f"scopes/{org_name}.yaml",
                 "--notes", "test notes")
        assert r.returncode == 0, r.stderr
        assert "created" in r.stdout
        r = _run("list", "--json")
        assert r.returncode == 0
        data = json.loads(r.stdout)
        names = [o["name"] for o in data]
        assert org_name in names

    def test_add_duplicate(self, org_name, db):
        _run("add", org_name)
        r = _run("add", org_name)
        assert r.returncode == 1
        assert "already exists" in r.stderr

    def test_show_json(self, org_name, db):
        _run("add", org_name, "--h1", "h1x")
        r = _run("show", org_name, "--json")
        assert r.returncode == 0, r.stderr
        data = json.loads(r.stdout)
        assert data["organisation"]["name"] == org_name
        assert data["organisation"]["h1_handle"] == "h1x"
        assert data["targets"] == []
        assert data["stats"]["exists"] is True

    def test_show_missing_returns_1(self, db):
        r = _run("show", "ghost-xxxxxxx")
        assert r.returncode == 1
        assert "not found" in r.stderr

    def test_update_partial(self, org_name, db):
        _run("add", org_name, "--h1", "old")
        r = _run("update", org_name, "--h1", "new")
        assert r.returncode == 0, r.stderr
        r = _run("show", org_name, "--json")
        data = json.loads(r.stdout)
        assert data["organisation"]["h1_handle"] == "new"

    def test_update_requires_a_flag(self, org_name, db):
        _run("add", org_name)
        r = _run("update", org_name)
        assert r.returncode == 2
        assert "nothing to update" in r.stderr

    def test_update_clear(self, org_name, db):
        _run("add", org_name, "--h1", "to-clear")
        r = _run("update", org_name, "--clear-h1")
        assert r.returncode == 0
        r = _run("show", org_name, "--json")
        data = json.loads(r.stdout)
        assert data["organisation"]["h1_handle"] is None

    def test_link_then_targets(self, org_name, db):
        _run("add", org_name)
        r = _run("link", "cli-target.example", org_name)
        assert r.returncode == 0, r.stderr
        assert "linked" in r.stdout
        r = _run("targets", org_name, "--json")
        assert r.returncode == 0
        apexes = [t["apex"] for t in json.loads(r.stdout)]
        assert "cli-target.example" in apexes

    def test_unlink(self, org_name, db):
        _run("add", org_name)
        _run("link", "u-target.example", org_name)
        r = _run("unlink", "u-target.example")
        assert r.returncode == 0, r.stderr
        r = _run("targets", "--unlinked", "--json")
        apexes = [t["apex"] for t in json.loads(r.stdout)]
        assert "u-target.example" in apexes

    def test_delete_refuses_with_targets(self, org_name, db):
        _run("add", org_name)
        _run("link", "d-target.example", org_name)
        r = _run("delete", org_name)
        assert r.returncode == 1
        assert "linked" in r.stderr

    def test_delete_force(self, org_name, db):
        _run("add", org_name)
        _run("link", "f-target.example", org_name)
        r = _run("delete", org_name, "--force")
        assert r.returncode == 0, r.stderr
        # Org gone, target row unlinked
        r2 = _run("targets", "--unlinked", "--json")
        apexes = [t["apex"] for t in json.loads(r2.stdout)]
        assert "f-target.example" in apexes

    def test_link_unknown_org(self, db):
        r = _run("link", "x.example", "ghost-xxxxx")
        assert r.returncode == 1
        assert "does not exist" in r.stderr
