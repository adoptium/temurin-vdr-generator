from cvereporter import fetch_vulnerabilities, nist_enhance
import json

# to run just one test: python3 -m pytest -v -k test_fetch -s (in this case, runs "test_fetch")
def test_fetch():
    with open("tests/data/open_jvg_dump_2023-01-17.html","r") as data:
        vulns = fetch_vulnerabilities.parse_to_cyclone(data, "2023-01-17")

        print(vulns)
        assert(len(vulns)==3)
        #todo: do some better assertions on the actual vulnerability contents here
        assert(vulns[0].id == "CVE-2023-21835")
        assert(list(vulns[0].affects)[0].ref == "security-libs/javax.net.ssl")
        assert(vulns[1].id == "CVE-2023-21830")
        assert(list(vulns[1].affects)[0].ref == "other-libs")
        assert(vulns[2].id == "CVE-2023-21843")
        assert(list(vulns[2].affects)[0].ref == "client-libs/javax.sound")


def test_parse_to_dict():
    with open("tests/data/open_jvg_dump_2023-01-17.html","r") as data:
        vulns = fetch_vulnerabilities.parse_to_dict(data, "2023-01-17")

        assert(len(vulns)==3)
        #todo: do some better assertions on the actual vulnerability contents here
        assert(vulns[0].id == "CVE-2023-21835")
        assert(list(vulns[0].affects)[0].ref == "security-libs/javax.net.ssl")
        assert(vulns[1].id == "CVE-2023-21830")
        assert(list(vulns[1].affects)[0].ref == "other-libs")
        assert(vulns[2].id == "CVE-2023-21843")
        assert(list(vulns[2].affects)[0].ref == "client-libs/javax.sound")

def test_nist_parse():
    with open("tests/data/nist_CVE-2023-21830.json", "r") as file_data:
        nist_data = json.load(file_data)["data"]
        relevant_parts = nist_enhance.extract_relevant_parts(nist_data)
        rtg = relevant_parts["ratings"][0]
        desc = relevant_parts["description"]
        assert(rtg["source"] == 'secalert_us@oracle.com')
        assert(rtg["score"] == 5.3)
        assert(rtg["severity"] == "MEDIUM")
        assert(rtg["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N")
        assert(len(relevant_parts["versions"])==4)