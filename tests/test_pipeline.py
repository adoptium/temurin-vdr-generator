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
        assert list(vulns[0].affects)[0].ref == "security-libs/javax.net.ssl"
        assert vulns[1].id == "CVE-2023-21830"
        assert list(vulns[1].affects)[0].ref == "other-libs"
        assert vulns[2].id == "CVE-2023-21843"
        assert list(vulns[2].affects)[0].ref == "client-libs/javax.sound"
        assert len(list(vulns[1].affects)[0].versions) == 2


def test_parse_to_dict():
    with open("tests/data/open_jvg_dump_2023-01-17.html", "r") as data:
        vulns = fetch_vulnerabilities.parse_to_dict(
            data, "2023-01-17", "www.fakeurl.com"
        )
        print(vulns)
        for cve in vulns:
            if cve["id"] == "CVE-2023-21830":
                assert len(cve["affected"]) == 2
            assert cve["ojvg_url"] == "www.fakeurl.com"


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

