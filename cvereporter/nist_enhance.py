from cyclonedx.model.vulnerability import (
    Vulnerability,
    VulnerabilitySource,
    VulnerabilityScoreSource,
    VulnerabilityRating,
)
import requests
import json

"""
this file has the utilities for downloading data about cves from NIST and updating Vulnerability objects with the data
"""


def fetch_nist(url: str, id: str) -> dict:
    data = None
    nist_resp = requests.get(url)
    if nist_resp.status_code != 200:
        print(
            "error fetching {}; status code: {}; text: {}".format(
                id, nist_resp.status_code, nist_resp.text
            )
        )
        """
            the most frequently seen error response is:
            error fetching CVE-2020-2805; status code: 403; text: <html><body><h1>403 Forbidden</h1> Request forbidden by administrative rules.
        """
    else:
        data = nist_resp.json()
        with open("data/nist_" + id + ".json", "w") as dest:
            json.dump({"url": url, "data": data}, dest, indent=True)
    return data


def extract_relevant_parts(nist_resp: dict) -> dict:
    # todo: this can use a unit test at some point
    resp_dict = {}
    ratings = []
    cve = nist_resp["vulnerabilities"][0]["cve"]
    # todo: do we have more than 1 cve in a resp?
    description = ""
    for desc in cve["descriptions"]:
        if desc["lang"] == "en":
            description = desc["value"]

    for metrics in cve["metrics"]["cvssMetricV31"]:
        # todo: do we need recommendations from NIST as well?
        relevant = {}
        relevant["source"] = metrics["source"]
        relevant["score"] = metrics["cvssData"]["baseScore"]
        relevant["severity"] = metrics["cvssData"]["baseSeverity"]
        relevant["method"] = "CVSSv3"  # is this always true?
        relevant["vector"] = metrics["cvssData"]["vectorString"]
        ratings.append(relevant)
    resp_dict["ratings"] = ratings
    resp_dict["description"] = description
    resp_dict["versions"] = extract_versions(cve["configurations"])
    return resp_dict


def extract_versions(cve_configs):
    vers = []
    for config in cve_configs:
        oracle_jdk_start = "oracle:jdk:"  # todo: do we care about non oracle
        for node in config["nodes"]:
            for match in node["cpeMatch"]:
                crit = match["criteria"]

                if oracle_jdk_start in crit:
                    ver = crit[crit.index(oracle_jdk_start) + len(oracle_jdk_start) :]
                    ver = ver[: ver.index(":")]  # todo: this truncates update version
                    vers.append(ver)
    return vers


def enhance(vulns: list[Vulnerability]):
    count = 0
    for vuln in vulns:
        count += 1
        id = vuln.id
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + id
        nist_resp = fetch_nist(url, id)
        if nist_resp is None:
            continue
        try:
            relevant = extract_relevant_parts(nist_resp)
        except KeyError:
            continue
        print("\n\n\n\n\n\nvuln: {} index {} ".format(id, count))
        # print(json.dumps(relevant, indent=True))
        for rating in relevant["ratings"]:
            # todo: convert the ratings into the cyclonedx enums?
            vr = VulnerabilityRating(
                source=VulnerabilitySource(url=rating["source"]),
                score=rating["score"],
                vector=rating["vector"],
                method=VulnerabilityScoreSource.CVSS_V3_1,
            )
            vuln.ratings.add(vr)
        vuln.description = relevant["description"]
        # for now - we use versions we extract when we download from OpenJDK Vulnerability group
        # this version extraction is tied to the Oracle JDKs which might not map directly to openjdk versions
        # that approach also has limitations: we have to do a bit of guesswork mapping cves to versions
        extract_versions_from_nist = False
        if extract_versions_from_nist:
            for affects in vuln.affects:
                for ver in relevant["versions"]:
                    affects.versions.add(ver)
        # print(vuln)
