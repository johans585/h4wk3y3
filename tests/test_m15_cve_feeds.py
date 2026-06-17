"""Unit tests for m15 — CVE intelligence feeds (PURE parsing/normalisation).

No network, no DB, no external binaries. We feed simulated KEV/EPSS/NVD JSON
and CSV into the pure pulling/normalisation helpers and assert the shape of
the normalised output + the merged `build_cve_row`.

The network pullers (`pull_kev`, `pull_epss`) are exercised by monkeypatching
`_http_get` so no socket is ever opened — only the parse logic runs.
"""
import json
import logging


from modules import m15_cve_feeds as m15

LOG = logging.getLogger("test-m15")


# ─── EPSS parsing ────────────────────────────────────────────────────────
class TestEpssParsing:
    def _csv(self) -> bytes:
        # EPSS file has a leading `#model_version` comment line before the header.
        return (
            "#model_version:v2023.03.01,score_date:2026-05-30T00:00:00+0000\n"
            "cve,epss,percentile\n"
            "CVE-2021-44228,0.97500,0.99900\n"
            "CVE-2014-0160,0.12345,0.55000\n"
            "BAD-ROW,notafloat,0.1\n"          # bad score → skipped
            "CVE-2099-9999,0.5\n"              # short row (no percentile) → skipped
        ).encode()

    def test_parses_valid_rows(self, monkeypatch):
        monkeypatch.setattr(m15, "_http_get", lambda url: self._csv())
        out = m15.pull_epss(LOG)
        assert out["CVE-2021-44228"] == (0.975, 0.999)
        assert out["CVE-2014-0160"] == (0.12345, 0.55)

    def test_skips_comment_and_malformed_rows(self, monkeypatch):
        monkeypatch.setattr(m15, "_http_get", lambda url: self._csv())
        out = m15.pull_epss(LOG)
        # only the 2 well-formed rows survive
        assert len(out) == 2
        assert "BAD-ROW" not in out
        assert "CVE-2099-9999" not in out

    def test_returns_floats(self, monkeypatch):
        monkeypatch.setattr(m15, "_http_get", lambda url: self._csv())
        out = m15.pull_epss(LOG)
        score, pct = out["CVE-2021-44228"]
        assert isinstance(score, float) and isinstance(pct, float)


# ─── KEV parsing ──────────────────────────────────────────────────────────
class TestKevParsing:
    def test_returns_vulnerabilities_list(self, monkeypatch):
        payload = json.dumps({
            "title": "CISA KEV",
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228", "vendorProject": "Apache",
                 "product": "Log4j2", "dateAdded": "2021-12-10",
                 "knownRansomwareCampaignUse": "Known"},
                {"cveID": "CVE-2017-0144", "vendorProject": "Microsoft",
                 "product": "SMBv1", "dateAdded": "2022-03-25",
                 "knownRansomwareCampaignUse": "Unknown"},
            ],
        }).encode()
        monkeypatch.setattr(m15, "_http_get", lambda url: payload)
        entries = m15.pull_kev(LOG)
        assert len(entries) == 2
        assert entries[0]["cveID"] == "CVE-2021-44228"

    def test_empty_catalog(self, monkeypatch):
        monkeypatch.setattr(m15, "_http_get", lambda url: b'{"vulnerabilities": []}')
        assert m15.pull_kev(LOG) == []

    def test_missing_vulnerabilities_key(self, monkeypatch):
        monkeypatch.setattr(m15, "_http_get", lambda url: b'{"title": "x"}')
        assert m15.pull_kev(LOG) == []


# ─── NVD field extractors (pure) ───────────────────────────────────────────
def _nvd_item():
    return {
        "cve": {
            "id": "CVE-2021-41773",
            "published": "2021-10-05T07:15:00.000",
            "descriptions": [
                {"lang": "es", "value": "descripcion"},
                {"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49"},
            ],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {
                    "baseScore": 7.5,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                }}],
                "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
            },
            "references": [
                {"url": "https://httpd.apache.org/security/vulnerabilities_24.html"},
                {"url": "https://example.com/advisory"},
                {"source": "no-url-here"},
            ],
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                        "vulnerable": True,
                    }, {
                        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                        "vulnerable": True,
                        "versionStartIncluding": "2.4.49",
                        "versionEndExcluding": "2.4.51",
                    }],
                    "children": [],
                }],
            }],
        },
    }


class TestNvdExtractors:
    def test_description_prefers_english(self):
        assert m15._description_from_nvd(_nvd_item()) == \
            "Path traversal in Apache HTTP Server 2.4.49"

    def test_description_none_item(self):
        assert m15._description_from_nvd(None) is None

    def test_cvss_v31_and_v2(self):
        v3, vector, v2 = m15._cvss_from_nvd(_nvd_item())
        assert v3 == 7.5
        assert vector.startswith("CVSS:3.1/")
        assert v2 == 5.0

    def test_cvss_none_item(self):
        assert m15._cvss_from_nvd(None) == (None, None, None)

    def test_refs_drops_entries_without_url(self):
        refs = m15._refs_from_nvd(_nvd_item())
        assert len(refs) == 2
        assert all(r.startswith("https://") for r in refs)

    def test_published_extraction(self):
        assert m15._published_from_nvd(_nvd_item()) == "2021-10-05T07:15:00.000"
        assert m15._published_from_nvd(None) is None

    def test_parse_cpes_raw_and_products(self):
        cpes, products = m15._parse_cpes(_nvd_item())
        # two distinct criteria → two raw CPEs
        assert len(cpes) == 2
        assert any("http_server:2.4.49" in c for c in cpes)
        # products vendor/product normalised
        assert all(p["vendor"] == "apache" for p in products)
        assert all(p["product"] == "http_server" for p in products)
        # exact-version product has "= 2.4.49" constraint
        exact = next(p for p in products if p["version_constraint"] == "= 2.4.49")
        assert exact is not None
        # range product maps versionStart/End operators
        ranged = next(p for p in products
                      if p["version_constraint"] and ">=" in p["version_constraint"])
        assert ">= 2.4.49" in ranged["version_constraint"]
        assert "< 2.4.51" in ranged["version_constraint"]

    def test_parse_cpes_empty_item(self):
        assert m15._parse_cpes(None) == ([], [])
        assert m15._parse_cpes({"cve": {}}) == ([], [])


# ─── build_cve_row merge logic (pure) ───────────────────────────────────────
class TestBuildCveRow:
    def test_full_merge_nvd_kev_epss_nuclei(self):
        kev = {"cveID": "CVE-2021-41773", "vendorProject": "Apache",
               "product": "HTTP Server", "dateAdded": "2021-10-07",
               "knownRansomwareCampaignUse": "Known",
               "shortDescription": "kev desc"}
        row = m15.build_cve_row(
            "CVE-2021-41773",
            kev=kev,
            epss=(0.96, 0.99),
            nuclei_tpl="http/cves/2021/CVE-2021-41773.yaml",
            nvd_item=_nvd_item(),
        )
        assert row["cve_id"] == "CVE-2021-41773"
        assert row["cvss_v3"] == 7.5
        assert row["cvss_v2"] == 5.0
        assert row["epss"] == 0.96
        assert row["epss_percentile"] == 0.99
        assert row["kev_flag"] == 1
        assert row["kev_ransomware"] == 1
        assert row["nuclei_template"] == "http/cves/2021/CVE-2021-41773.yaml"
        # NVD description wins over KEV shortDescription
        assert "Path traversal" in row["description"]
        # vendor taken from parsed CPE products
        assert row["vendor"] == "apache"
        # source_feeds is JSON list with all 4 signals
        feeds = json.loads(row["source_feeds"])
        assert set(feeds) == {"kev", "epss", "nvd", "nuclei"}
        # cpes / products / refs are JSON-encoded
        assert isinstance(json.loads(row["cpes"]), list)
        assert isinstance(json.loads(row["products"]), list)
        assert isinstance(json.loads(row["refs"]), list)

    def test_kev_only_fallbacks(self):
        # No NVD item → description + vendor + product synthesised from KEV.
        kev = {"cveID": "CVE-2017-0144", "vendorProject": "Microsoft",
               "product": "Windows SMBv1", "dateAdded": "2022-03-25",
               "shortDescription": "SMBv1 RCE",
               "knownRansomwareCampaignUse": "Unknown"}
        row = m15.build_cve_row("CVE-2017-0144", kev=kev, epss=None,
                                nuclei_tpl=None, nvd_item=None)
        assert row["description"] == "SMBv1 RCE"
        assert row["vendor"] == "microsoft"          # lowercased
        assert row["cvss_v3"] is None
        assert row["epss"] is None
        assert row["kev_flag"] == 1
        assert row["kev_ransomware"] == 0            # "Unknown" → 0
        # published_at falls back to KEV dateAdded
        assert row["published_at"] == "2022-03-25"
        products = json.loads(row["products"])
        assert products[0]["product"] == "windows smbv1"
        feeds = json.loads(row["source_feeds"])
        assert feeds == ["kev"]

    def test_nuclei_only_no_kev_no_nvd(self):
        row = m15.build_cve_row("CVE-2024-0001", kev=None, epss=None,
                                nuclei_tpl="http/cves/2024/CVE-2024-0001.yaml",
                                nvd_item=None)
        assert row["kev_flag"] == 0
        assert row["vendor"] is None
        assert row["products"] is None
        assert json.loads(row["source_feeds"]) == ["nuclei"]


# ─── nuclei template scanner (pure filesystem, no binary) ──────────────────
class TestScanNucleiTemplates:
    def test_indexes_cve_yaml_files(self, tmp_path):
        d = tmp_path / "http" / "cves"
        sub = d / "2021"
        sub.mkdir(parents=True)
        (sub / "CVE-2021-41773.yaml").write_text("id: CVE-2021-41773\n")
        (sub / "CVE-2021-44228.yaml").write_text("id: CVE-2021-44228\n")
        (sub / "tracee.yaml").write_text("id: tracee\n")   # non-CVE → ignored
        out = m15.scan_nuclei_templates([str(d)], LOG)
        assert set(out.keys()) == {"CVE-2021-41773", "CVE-2021-44228"}
        # paths are stored prefixed with http/cves/
        assert out["CVE-2021-41773"].startswith("http/cves/")
        assert out["CVE-2021-41773"].endswith("CVE-2021-41773.yaml")

    def test_missing_dir_returns_empty(self, tmp_path):
        out = m15.scan_nuclei_templates([str(tmp_path / "does-not-exist")], LOG)
        assert out == {}

    def test_case_insensitive_match(self, tmp_path):
        d = tmp_path / "http" / "cves"
        d.mkdir(parents=True)
        (d / "cve-2022-1234.yaml").write_text("id: x\n")
        out = m15.scan_nuclei_templates([str(d)], LOG)
        # normalised to uppercase
        assert "CVE-2022-1234" in out


# ─── _nvd_iso formatting (pure) ────────────────────────────────────────────
def test_nvd_iso_format():
    from datetime import datetime
    s = m15._nvd_iso(datetime(2024, 1, 5, 13, 30, 45))
    assert s == "2024-01-05T13:30:45.000"
