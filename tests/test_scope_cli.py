"""Tests for `argus scope ...` CLI subcommand (Étape 2.2).

Driven via subprocess so the argparse wiring inside h4wk3y3.py is also covered.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
ARGUS_PY = REPO / "h4wk3y3.py"


def _run(*args, cwd: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    # Ensure imports resolve against the checkout under test.
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, str(ARGUS_PY), "scope", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
    )


@pytest.fixture
def cli_root(tmp_path):
    """Stand up a minimal argus checkout layout (scopes/ dir + an empty
    wildcards file) inside tmp_path so the CLI auto-discovery resolves
    against a controlled root.

    We can't easily re-root h4wk3y3.py (it reads from __file__), so instead
    we copy the example scope file into the *real* scopes/ dir for the
    duration of the test. To stay hermetic, we use a unique apex name
    that won't collide with anything checked in.
    """
    apex = "scopeclitest.example"
    scopes_dir = REPO / "scopes"
    scopes_dir.mkdir(exist_ok=True)
    f = scopes_dir / f"{apex}.yaml"
    f.write_text(
        "organisation: scopeclitest\n"
        f"apex: {apex}\n"
        "scope:\n"
        '  in:  ["*.scopeclitest.example", "*.scopeclitest-cdn.example"]\n'
        '  out: ["*.scopeclitest-internal.example"]\n'
        "  restrictions:\n"
        '    - host: "checkout.scopeclitest.example"\n'
        "      max_rps: 5\n"
        '    - path: "/api/payments/*"\n'
        "      disabled: true\n",
        encoding="utf-8",
    )
    yield {"apex": apex, "file": f, "cwd": REPO}
    try:
        f.unlink()
    except FileNotFoundError:
        pass


class TestScopeCli:
    def test_list_includes_fixture(self, cli_root):
        r = _run("list", cwd=cli_root["cwd"])
        assert r.returncode == 0, r.stderr
        assert "scopeclitest" in r.stdout

    def test_show_uses_yaml_source(self, cli_root):
        r = _run("show", cli_root["apex"], cwd=cli_root["cwd"])
        assert r.returncode == 0, r.stderr
        assert "source       : yaml:" in r.stdout
        assert "organisation : scopeclitest" in r.stdout
        assert "restrictions : 2" in r.stdout

    def test_show_json(self, cli_root):
        r = _run("show", cli_root["apex"], "--json", cwd=cli_root["cwd"])
        assert r.returncode == 0, r.stderr
        data = json.loads(r.stdout)
        assert data["organisation"] == "scopeclitest"
        assert data["apex"] == cli_root["apex"]
        assert len(data["restrictions"]) == 2

    def test_check_apex_in(self, cli_root):
        r = _run("check", cli_root["apex"],
                 f"https://api.{cli_root['apex']}/v1", cwd=cli_root["cwd"])
        assert r.returncode == 0, r.stderr
        assert "IN" in r.stdout
        assert "reason : apex" in r.stdout

    def test_check_extra_in(self, cli_root):
        r = _run("check", cli_root["apex"],
                 "https://static.scopeclitest-cdn.example/asset.js",
                 cwd=cli_root["cwd"])
        assert r.returncode == 0, r.stderr
        assert "IN" in r.stdout
        assert "reason : extra:*.scopeclitest-cdn.example" in r.stdout

    def test_check_out_explicit(self, cli_root):
        r = _run("check", cli_root["apex"],
                 "https://secret.scopeclitest-internal.example/admin",
                 cwd=cli_root["cwd"])
        assert r.returncode == 1, r.stderr
        assert "OUT" in r.stdout
        assert "out:*.scopeclitest-internal.example" in r.stdout

    def test_check_restriction_disabled_rejects(self, cli_root):
        r = _run("check", cli_root["apex"],
                 f"https://checkout.{cli_root['apex']}/api/payments/charge",
                 cwd=cli_root["cwd"])
        assert r.returncode == 1, r.stderr
        assert "OUT" in r.stdout
        assert "restriction:disabled" in r.stdout

    def test_check_restriction_max_rps_is_informational(self, cli_root):
        r = _run("check", cli_root["apex"],
                 f"https://checkout.{cli_root['apex']}/cart",
                 cwd=cli_root["cwd"])
        assert r.returncode == 0, r.stderr
        assert "IN" in r.stdout
        # Restriction visible in output
        assert "max_rps=5" in r.stdout

    def test_diff_file(self, cli_root, tmp_path):
        urls = tmp_path / "urls.txt"
        urls.write_text(
            "\n".join([
                f"https://api.{cli_root['apex']}/a",
                f"https://api.{cli_root['apex']}/b",
                "https://google.com/trk",
                "https://internal.scopeclitest-internal.example/admin",
                "# comment ignored",
            ]),
            encoding="utf-8",
        )
        r = _run("diff", cli_root["apex"], str(urls), cwd=cli_root["cwd"])
        assert r.returncode == 0, r.stderr
        assert "Total candidates : 4" in r.stdout
        assert "In scope         : 2" in r.stdout
        assert "Out of scope     : 2" in r.stdout
        # reasons should be summarised
        assert "out:" in r.stdout or "no match" in r.stdout

    def test_diff_missing_file(self, cli_root):
        r = _run("diff", cli_root["apex"], "/nonexistent/urls.txt",
                 cwd=cli_root["cwd"])
        assert r.returncode == 2
        assert "not found" in r.stderr

    def test_check_unknown_apex_falls_back_to_wildcards(self, cli_root):
        # apex we don't have a yaml for — CLI should fall back to wildcards
        # and report source=wildcards, NOT crash.
        r = _run("check", "this-apex-has-no-yaml.example",
                 "https://this-apex-has-no-yaml.example/", cwd=cli_root["cwd"])
        # Whether it's IN or OUT depends on the wildcards file; we just
        # care that the command runs end-to-end and prints the source.
        assert "source=wildcards" in r.stdout
