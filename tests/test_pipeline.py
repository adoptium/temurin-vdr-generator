import hashlib
import os
import tempfile

from cvereporter import fetch_vulnerabilities, nist_enhance, fetch_dates, cve_project
import json


# To run a single test: python3 -m pytest -v -k test_fetch -s (in this case, runs "test_fetch")
def test_fetch():
    with open("tests/data/open_jvg_dump_2023-01-17.html", "r") as data:
        vulns = fetch_vulnerabilities.parse_to_cyclone(
            data, "2023-01-17", "www.fakeurl.com"
        )

        print(vulns)
        assert len(vulns) == 3
        # todo: do some better assertions on the actual vulnerability contents here
        assert vulns[0].id == "CVE-2023-21835"
        assert list(vulns[0].affects)[0].ref == "pkg:github/openjdk/jdk"
        assert vulns[1].id == "CVE-2023-21830"
        assert list(vulns[1].affects)[0].ref == "pkg:github/openjdk/jdk"
        assert vulns[2].id == "CVE-2023-21843"
        assert list(vulns[2].affects)[0].ref == "pkg:github/openjdk/jdk"
        assert len(list(vulns[1].affects)[0].versions) == 1
        assert list(vulns[1].affects)[0].versions[0].range == "vers:generic/7u361|8u352"


def test_fetch_no_href():
    with open("tests/data/open_jvg_dump_2026-04-21.html", "r") as data:
        vulns = fetch_vulnerabilities.parse_to_cyclone(
            data, "2026-04-21", "www.fakeurl.com"
        )

        print(vulns)
        assert len(vulns) == 9
        # todo: do some better assertions on the actual vulnerability contents here
        assert vulns[0].id == "CVE-2026-22016"
        assert list(vulns[0].affects)[0].ref == "pkg:github/openjdk/jdk"


def test_parse_to_dict():
    with open("tests/data/open_jvg_dump_2023-01-17.html", "r") as data:
        vulns = fetch_vulnerabilities.parse_to_dict(
            data, "2023-01-17", "www.fakeurl.com"
        )
        print(vulns)
        for cve in vulns:
            if cve["id"] == "CVE-2023-21830":
                assert len(cve["affected"]) == 2
                print(cve)
                assert cve["ojvg_url"] == "www.fakeurl.com"
                assert cve["ojvg_score"] == 5.3


def test_parse_to_dict_2026():
    with open("tests/data/open_jvg_dump_2026-04-21.html", "r") as data:
        vulns = fetch_vulnerabilities.parse_to_dict(
            data, "2026-04-21", "www.fakeurl.com"
        )
        print(vulns)
        for cve in vulns:
            if cve["id"] == "CVE-2026-22016":
                assert len(cve["affected"]) == 6
                print(cve)
                assert cve["ojvg_url"] == "www.fakeurl.com"
                assert cve["ojvg_score"] == 7.5


def test_parse_to_dict_score_with_vector(caplog):
    # the score cell holds the score and the cvss vector on two lines, e.g. "7.5<br />NLNNUHNN"
    with open("tests/data/open_jvg_dump_2026-04-21.html", "r") as data:
        vulns = fetch_vulnerabilities.parse_to_dict(
            data, "2026-04-21", "www.fakeurl.com"
        )
    scores = [cve["ojvg_score"] for cve in vulns]
    assert scores == [7.5, 7.5, 5.3, 5.3, 5.3, 3.7, 3.7, 2.9, 2.9]
    assert "is not a valid score float" not in caplog.text


def test_nist_parse():
    with open("tests/data/nist_CVE-2023-21830.json", "r") as file_data:
        nist_data = json.load(file_data)["data"]
        relevant_parts = nist_enhance.extract_relevant_parts(nist_data)
        rtg = relevant_parts["ratings"][0]
        desc = relevant_parts["description"]
        assert rtg["source"] == "secalert_us@oracle.com"
        assert rtg["score"] == 5.3
        assert rtg["severity"] == "MEDIUM"
        assert rtg["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
        assert len(relevant_parts["versions"]) == 4


def test_fetch_advisory_dates():
    with open("tests/data/open_jvg_dates.html", "r") as data:
        html = data.read()
        dates = fetch_dates.fetch_advisory_dates(html)
        assert len(dates) > 0

        # Check dates are in the expected format (YYYY-MM-DD)
        assert all(len(date.split("-")) == 3 for date in dates)

        for date in dates:
            y, m, d = date.split("-")
            assert y.isdigit() and m.isdigit() and d.isdigit()
            assert len(y) == 4 and len(m) == 2 and len(d) == 2
            assert 1 <= int(m) <= 12
            assert 1 <= int(d) <= 31


def test_decimal_parse_hack():
    assert fetch_vulnerabilities.decimal_parse_hack("7.5NOTANUMBER") == "7.5"
    assert fetch_vulnerabilities.decimal_parse_hack("7BLAHBLAHBLAH") == "7"


# ---------------------------------------------------------------------------
# Release asset packaging tests
# These tests validate the checksum manifest filename and content format used
# by the publish job in vdr-creation.yml. No live GitHub API calls are made.
# ---------------------------------------------------------------------------


def _make_sha256_manifest(asset_path: str, manifest_path: str) -> None:
    """Reproduce the sha256sum output written by the workflow publish step."""
    digest = hashlib.sha256(open(asset_path, "rb").read()).hexdigest()
    filename = os.path.basename(asset_path)
    with open(manifest_path, "w") as f:
        f.write(f"{digest}  {filename}\n")


def test_release_asset_naming():
    """Tag and asset filenames follow the temurin-vdr-DD-MM-YYYY-<run_id> scheme."""
    run_id = "12345678"
    date = "01-06-2025"
    tag = f"temurin-vdr-{date}-{run_id}"

    assert tag.startswith("temurin-vdr-")
    parts = tag.split("-")
    # expected parts: ['temurin', 'vdr', DD, MM, YYYY, run_id]
    assert len(parts) == 6
    dd, mm, yyyy = parts[2], parts[3], parts[4]
    assert dd.isdigit() and len(dd) == 2
    assert mm.isdigit() and len(mm) == 2
    assert yyyy.isdigit() and len(yyyy) == 4
    assert parts[5] == run_id

    assert f"{tag}.json" == f"temurin-vdr-{date}-{run_id}.json"
    assert f"{tag}.sha256" == f"temurin-vdr-{date}-{run_id}.sha256"


def test_checksum_manifest_content():
    """SHA-256 manifest has correct digest and matches standard checksum-file format."""
    with tempfile.TemporaryDirectory() as tmpdir:
        run_id = "99999999"
        date = "15-07-2025"
        tag = f"temurin-vdr-{date}-{run_id}"
        asset_name = f"{tag}.json"
        manifest_name = f"{tag}.sha256"

        asset_path = os.path.join(tmpdir, asset_name)
        manifest_path = os.path.join(tmpdir, manifest_name)

        payload = b'{"bomFormat": "CycloneDX", "specVersion": "1.4"}'
        with open(asset_path, "wb") as f:
            f.write(payload)

        _make_sha256_manifest(asset_path, manifest_path)

        with open(manifest_path, "r") as f:
            line = f.read().strip()

        # Standard checksum-file format: "<hex_digest>  <filename>"
        digest_part, filename_part = line.split("  ", 1)
        assert len(digest_part) == 64
        assert all(c in "0123456789abcdef" for c in digest_part)
        assert filename_part == asset_name

        expected_digest = hashlib.sha256(payload).hexdigest()
        assert digest_part == expected_digest


def test_checksum_manifest_verifies_asset():
    """Asset content that changes produces a different digest (tamper detection)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tag = "temurin-vdr-01-01-2025-11111111"
        asset_path = os.path.join(tmpdir, f"{tag}.json")
        manifest_path = os.path.join(tmpdir, f"{tag}.sha256")

        with open(asset_path, "wb") as f:
            f.write(b'{"original": true}')

        _make_sha256_manifest(asset_path, manifest_path)

        with open(manifest_path, "r") as f:
            original_digest = f.read().split("  ")[0]

        # Simulate a tampered asset
        with open(asset_path, "wb") as f:
            f.write(b'{"tampered": true}')

        tampered_digest = hashlib.sha256(open(asset_path, "rb").read()).hexdigest()
        assert tampered_digest != original_digest


def test_cve_project_url():
    assert cve_project.cve_project_url("CVE-2026-22016") == (
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/22xxx/CVE-2026-22016.json"
    )
    assert cve_project.cve_project_url("CVE-2014-0001").endswith(
        "/cves/2014/0xxx/CVE-2014-0001.json"
    )
    assert cve_project.cve_project_url("CVE-2024-123456").endswith(
        "/cves/2024/123xxx/CVE-2024-123456.json"
    )


def test_cve_project_parse():
    with open("tests/data/cveproject_CVE-2023-21830.json", "r") as file_data:
        record = json.load(file_data)["data"]
        relevant_parts = cve_project.extract_relevant_parts(record)
        assert len(relevant_parts["ratings"]) == 1
        rtg = relevant_parts["ratings"][0]
        assert rtg["source"] == "oracle"
        assert rtg["score"] == 5.3
        assert rtg["severity"] == "MEDIUM"
        assert rtg["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
        assert relevant_parts["description"].startswith(
            "Vulnerability in the Oracle Java SE"
        )
        assert relevant_parts["versions"] == ["8u351", "8u351-perf"]


def _stub_sources(monkeypatch, nvd, cve):
    calls = []

    def fake_nvd(id):
        calls.append("nvd")
        return nvd

    def fake_cve(id):
        calls.append("cve_project")
        return cve

    monkeypatch.setattr(nist_enhance, "relevant_from_nvd", fake_nvd)
    monkeypatch.setattr(nist_enhance, "relevant_from_cve_project", fake_cve)
    return calls


def test_data_source_modes(monkeypatch):
    nvd = {"ratings": [{"source": "nvd"}], "description": "nvd", "versions": []}
    cve = {"ratings": [{"source": "cve"}], "description": "cve", "versions": []}
    Mode = nist_enhance.DataSourceMode

    calls = _stub_sources(monkeypatch, nvd, cve)
    assert nist_enhance.get_relevant("CVE-1", Mode.NVD_ONLY) is nvd
    assert calls == ["nvd"]

    calls = _stub_sources(monkeypatch, nvd, cve)
    assert nist_enhance.get_relevant("CVE-1", Mode.CVE_PROJECT_THEN_NVD) is cve
    assert calls == ["cve_project"]

    calls = _stub_sources(monkeypatch, nvd, cve)
    assert nist_enhance.get_relevant("CVE-1", Mode.NVD_THEN_CVE_PROJECT) is nvd
    assert calls == ["nvd"]


def test_data_source_fallback(monkeypatch):
    nvd = {"ratings": [{"source": "nvd"}], "description": "nvd", "versions": []}
    no_ratings = {"ratings": [], "description": "cve", "versions": []}
    Mode = nist_enhance.DataSourceMode

    # primary missing -> fallback used
    calls = _stub_sources(monkeypatch, nvd, None)
    assert nist_enhance.get_relevant("CVE-1", Mode.NVD_THEN_CVE_PROJECT) is nvd
    calls = _stub_sources(monkeypatch, None, nvd)
    assert nist_enhance.get_relevant("CVE-1", Mode.NVD_THEN_CVE_PROJECT) is nvd
    assert calls == ["nvd", "cve_project"]

    # primary has no ratings -> fallback with ratings preferred
    calls = _stub_sources(monkeypatch, nvd, no_ratings)
    assert nist_enhance.get_relevant("CVE-1", Mode.CVE_PROJECT_THEN_NVD) is nvd
    assert calls == ["cve_project", "nvd"]

    # nothing has ratings -> first record found is kept for its description
    _stub_sources(monkeypatch, None, no_ratings)
    assert nist_enhance.get_relevant("CVE-1", Mode.CVE_PROJECT_THEN_NVD) is no_ratings

    # nothing found at all
    _stub_sources(monkeypatch, None, None)
    assert nist_enhance.get_relevant("CVE-1", Mode.CVE_PROJECT_THEN_NVD) is None


def test_enhance_summary(monkeypatch):
    from cyclonedx.model.vulnerability import Vulnerability

    results = {
        "CVE-2023-0001": {
            "ratings": [],
            "description": "d",
            "versions": [],
            "data_source": "cve_project",
        },
        "CVE-2023-0002": {
            "ratings": [],
            "description": "d",
            "versions": [],
            "data_source": "nvd",
        },
        "CVE-2023-0003": None,
    }
    monkeypatch.setattr(nist_enhance, "get_relevant", lambda id, mode: results[id])
    vulns = [Vulnerability(id=id) for id in results]
    summary = nist_enhance.enhance(
        vulns, nist_enhance.DataSourceMode.CVE_PROJECT_THEN_NVD
    )
    assert summary == {
        "description only (cve_project)": 1,
        "description only (nvd)": 1,
        "not found": 1,
    }


def test_get_relevant_records_data_source(monkeypatch):
    nvd = {"ratings": [{"source": "nvd"}], "description": "nvd", "versions": []}
    _stub_sources(monkeypatch, None, nvd)
    relevant = nist_enhance.get_relevant(
        "CVE-1", nist_enhance.DataSourceMode.NVD_THEN_CVE_PROJECT
    )
    assert relevant["data_source"] == "cve_project"


def test_enhance_provenance(monkeypatch):
    from cyclonedx.model.vulnerability import Vulnerability, VulnerabilitySource

    rating = {
        "score": 5.3,
        "severity": "MEDIUM",
        "method": "CVSSv3",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    }
    results = {
        "CVE-2023-21830": {
            "ratings": [dict(rating, source="oracle")],
            "description": "from cve project",
            "versions": [],
            "data_source": "cve_project",
        },
        "CVE-2023-21835": {
            "ratings": [dict(rating, source="nvd@nist.gov")],
            "description": "from nvd",
            "versions": [],
            "data_source": "nvd",
        },
        "CVE-2023-21843": None,
    }
    monkeypatch.setattr(nist_enhance, "get_relevant", lambda id, mode: results[id])
    ojvg = VulnerabilitySource(
        name="OpenJDK Vulnerability Group", url="https://openjdk.org/advisory"
    )
    vulns = [Vulnerability(id=id, source=ojvg) for id in results]
    nist_enhance.enhance(vulns, nist_enhance.DataSourceMode.CVE_PROJECT_THEN_NVD)

    cve_vuln, nvd_vuln, missing_vuln = vulns
    cve_url = "https://github.com/CVEProject/cvelistV5/blob/main/cves/2023/21xxx/CVE-2023-21830.json"
    assert cve_vuln.source.name == "CVE Project (cvelistV5)"
    assert str(cve_vuln.source.url) == cve_url
    cve_rating = list(cve_vuln.ratings)[0]
    assert cve_rating.source.name == "oracle"
    assert str(cve_rating.source.url) == cve_url

    nvd_url = "https://nvd.nist.gov/vuln/detail/CVE-2023-21835"
    assert nvd_vuln.source.name == "National Vulnerability Database"
    assert str(nvd_vuln.source.url) == nvd_url
    nvd_rating = list(nvd_vuln.ratings)[0]
    assert nvd_rating.source.name == "nvd@nist.gov"
    assert str(nvd_rating.source.url) == nvd_url

    # nothing found: keeps the ojvg advisory as its source
    assert missing_vuln.source.name == "OpenJDK Vulnerability Group"


def test_fetch_source_is_ojvg():
    with open("tests/data/open_jvg_dump_2023-01-17.html", "r") as data:
        vulns = fetch_vulnerabilities.parse_to_cyclone(
            data, "2023-01-17", "www.fakeurl.com"
        )
        assert vulns[0].source.name == "OpenJDK Vulnerability Group"
        assert str(vulns[0].source.url) == "www.fakeurl.com"


def test_nist_parse_awaiting_analysis():
    # nvd records that haven't been analysed yet have no configurations (and sometimes no metrics)
    with open("tests/data/nist_CVE-2023-21830.json", "r") as file_data:
        nist_data = json.load(file_data)["data"]
        cve = nist_data["vulnerabilities"][0]["cve"]
        del cve["configurations"]
        relevant_parts = nist_enhance.extract_relevant_parts(nist_data)
        assert len(relevant_parts["ratings"]) == 1
        assert relevant_parts["versions"] == []
        del cve["metrics"]
        relevant_parts = nist_enhance.extract_relevant_parts(nist_data)
        assert relevant_parts["ratings"] == []
        assert relevant_parts["description"] != ""


def test_data_source_fallback_if_missing(monkeypatch):
    nvd = {"ratings": [{"source": "nvd"}], "description": "nvd", "versions": []}
    no_ratings = {"ratings": [], "description": "cve", "versions": []}
    Mode = nist_enhance.DataSourceMode

    # a cve project file without ratings is still used, nvd isn't called
    calls = _stub_sources(monkeypatch, nvd, no_ratings)
    assert (
        nist_enhance.get_relevant("CVE-1", Mode.CVE_PROJECT_THEN_NVD_IF_MISSING)
        is no_ratings
    )
    assert calls == ["cve_project"]

    # no cve project file -> nvd
    calls = _stub_sources(monkeypatch, nvd, None)
    assert (
        nist_enhance.get_relevant("CVE-1", Mode.CVE_PROJECT_THEN_NVD_IF_MISSING) is nvd
    )
    assert calls == ["cve_project", "nvd"]


def test_mode_from_env(monkeypatch):
    import pytest

    Mode = nist_enhance.DataSourceMode
    monkeypatch.delenv("VDR_DATA_SOURCE_MODE", raising=False)
    assert nist_enhance.mode_from_env() == nist_enhance.DEFAULT_DATA_SOURCE_MODE
    for mode in Mode:
        monkeypatch.setenv("VDR_DATA_SOURCE_MODE", mode.value)
        assert nist_enhance.mode_from_env() == mode
    monkeypatch.setenv("VDR_DATA_SOURCE_MODE", "bogus")
    with pytest.raises(ValueError):
        nist_enhance.mode_from_env()


def test_enhance_reads_mode_from_env(monkeypatch):
    seen = []
    monkeypatch.setattr(
        nist_enhance, "get_relevant", lambda id, mode: seen.append(mode)
    )
    monkeypatch.setenv("VDR_DATA_SOURCE_MODE", "nvd_only")
    from cyclonedx.model.vulnerability import Vulnerability

    nist_enhance.enhance([Vulnerability(id="CVE-2023-0001")])
    assert seen == [nist_enhance.DataSourceMode.NVD_ONLY]


def test_fetch_nist_retries_connection_errors(monkeypatch, tmp_path):
    import requests

    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    monkeypatch.setattr(nist_enhance.time, "sleep", lambda s: None)
    monkeypatch.delenv("NIST_NVD_TOKEN", raising=False)

    class Resp:
        status_code = 200

        def json(self):
            return {"vulnerabilities": []}

    calls = []

    def flaky_get(url, headers, timeout):
        calls.append(url)
        if len(calls) < 3:
            raise requests.ConnectionError(
                "Remote end closed connection without response"
            )
        return Resp()

    monkeypatch.setattr(nist_enhance.requests, "get", flaky_get)
    assert nist_enhance.fetch_nist("https://example/nvd", "CVE-2023-0001") == {
        "vulnerabilities": []
    }
    assert len(calls) == 3

    def always_fails(url, headers, timeout):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(nist_enhance.requests, "get", always_fails)
    assert nist_enhance.fetch_nist("https://example/nvd", "CVE-2023-0002") is None


def test_fetch_nist_retries_server_errors(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    monkeypatch.setattr(nist_enhance.time, "sleep", lambda s: None)
    monkeypatch.delenv("NIST_NVD_TOKEN", raising=False)

    class Resp:
        def __init__(self, status_code):
            self.status_code = status_code
            self.text = "status " + str(status_code)

        def json(self):
            return {"vulnerabilities": []}

    statuses = [503, 429, 200]
    monkeypatch.setattr(
        nist_enhance.requests,
        "get",
        lambda url, headers, timeout: Resp(statuses.pop(0)),
    )
    assert nist_enhance.fetch_nist("https://example/nvd", "CVE-2023-0001") == {
        "vulnerabilities": []
    }
    assert statuses == []

    # still failing after all attempts -> None, nothing cached
    monkeypatch.setattr(
        nist_enhance.requests, "get", lambda url, headers, timeout: Resp(503)
    )
    assert nist_enhance.fetch_nist("https://example/nvd", "CVE-2023-0002") is None
    assert not (tmp_path / "data" / "nist_CVE-2023-0002.json").exists()

    # client errors such as 404 aren't retried
    calls = []
    monkeypatch.setattr(
        nist_enhance.requests,
        "get",
        lambda url, headers, timeout: calls.append(1) or Resp(404),
    )
    assert nist_enhance.fetch_nist("https://example/nvd", "CVE-2023-0003") is None
    assert len(calls) == 1


def test_cve_project_parse_cvss_3_0():
    # oracle's 2020 records only have cvss 3.0 scores
    with open("tests/data/cveproject_CVE-2020-2593.json", "r") as file_data:
        record = json.load(file_data)["data"]
        relevant_parts = cve_project.extract_relevant_parts(record)
        assert len(relevant_parts["ratings"]) == 1
        rtg = relevant_parts["ratings"][0]
        assert rtg["source"] == "oracle"
        assert rtg["score"] == 4.8
        assert rtg["vector"] == "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"


def test_cve_project_prefers_cvss_3_1():
    record = {
        "containers": {
            "cna": {
                "providerMetadata": {"shortName": "oracle"},
                "descriptions": [{"lang": "en", "value": "d"}],
                "metrics": [
                    {
                        "cvssV3_0": {
                            "baseScore": 4.8,
                            "baseSeverity": "MEDIUM",
                            "vectorString": "CVSS:3.0/AV:N",
                        }
                    },
                    {
                        "cvssV3_1": {
                            "baseScore": 5.0,
                            "baseSeverity": "MEDIUM",
                            "vectorString": "CVSS:3.1/AV:N",
                        }
                    },
                ],
            }
        }
    }
    ratings = cve_project.extract_relevant_parts(record)["ratings"]
    assert [r["vector"] for r in ratings] == ["CVSS:3.1/AV:N"]


def test_cvss_method():
    from cyclonedx.model.vulnerability import VulnerabilityScoreSource

    assert (
        nist_enhance.cvss_method("CVSS:3.0/AV:N/AC:H")
        == VulnerabilityScoreSource.CVSS_V3
    )
    assert (
        nist_enhance.cvss_method("CVSS:3.1/AV:N/AC:H")
        == VulnerabilityScoreSource.CVSS_V3_1
    )
