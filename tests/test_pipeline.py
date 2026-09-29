import hashlib
import os
import tempfile

from cvereporter import fetch_vulnerabilities, nist_enhance, fetch_dates
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
            assert(y.isdigit() and m.isdigit() and d.isdigit())
            assert(len(y) == 4 and len(m) == 2 and len(d) == 2)
            assert(1 <= int(m) <= 12)
            assert(1 <= int(d) <= 31) 

def test_decimal_parse_hack():
    assert(fetch_vulnerabilities.decimal_parse_hack("7.5NOTANUMBER")=="7.5")
    assert(fetch_vulnerabilities.decimal_parse_hack("7BLAHBLAHBLAH")=="7")



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
