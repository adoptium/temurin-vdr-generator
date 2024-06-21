#!/usr/bin/env python3

import json
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from cyclonedx.model.vulnerability import (
    Vulnerability,
    VulnerabilityScoreSource,
    VulnerabilitySource,
    VulnerabilityRating,
    BomTarget,
)

"""
Utilities to fetch data from OJVG and convert it to intermediate representations/CycloneDX structure
"""


def fetch_cves(date: str) -> list[Vulnerability]:
    return dict_to_vulns(fetch_dicts(date))


def fetch_dicts(date: str):
    cve_text, url = retrieve_cves_from_internet(date)
    dicts = parse_to_dict(cve_text, date, url)
    return dicts


def retrieve_cves_from_internet(date: str) -> str:
    # fetch the CVEs for the given date
    url = "https://openjdk.org/groups/vulnerability/advisories/" + date
    print(url)
    try:
        r = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/109.0",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Referer": "http://www.google.com/",
            },
        )
    except requests.exceptions.ReadTimeout:
        return None, None
    if r.status_code == 404:
        return None, None
    resp_text = r.text
    # todo: make this configurable
    with open("data/open_jvg_dump_" + date + ".html", "w") as dump:
        dump.write(resp_text)
    return resp_text, url


def parse_to_cyclone(resp_text: str, date: str, ojvg_url: str) -> list[Vulnerability]:
    dicts = parse_to_dict(resp_text, date, ojvg_url)
    return dict_to_vulns(dicts)


def populate_column_headers(column_headers, header):
    if "CVE ID" in header.text:
        current_column_header = header
        while current_column_header is not None:
            column_headers.append(current_column_header.text)
            current_column_header = current_column_header.find_next_sibling("th")


# Extracted_affected is the top level versions affected by any cves in this OJVG Email.
# Affected_major_versions is the major java versions affected by this particular cve.
# This function figures out which minor versions belong to the affected major versions.
# This isn't a great heuristic (two cves might affect different minor versions of the same major version),
# but it's the best we can get from the OJVG email.
def intersect_major_versions_with_extracted_affected(
    extracted_affected, affected_major_versions
):
    affected_versions = []
    for version in extracted_affected:
        if (
            "." in version
            and int(version[0 : version.index(".")]) in affected_major_versions
        ):
            affected_versions.append(version)

        elif (
            "u" in version
            and int(version[0 : version.index("u")]) in affected_major_versions
        ):
            affected_versions.append(version)
        elif version.isnumeric() and int(version) in affected_major_versions:
            affected_versions.append(version)
    return affected_versions


def parse_to_dict(resp_text: str, date: str, ojvg_url: str) -> list[dict]:
    if resp_text is None:
        return None
    soup = BeautifulSoup(resp_text, "html.parser")

    # find the versions affected
    header_string = soup.find(name="p")
    extracted_affected = extract_affected(header_string.text)

    # find the table with the CVEs
    table = soup.find("table", attrs={"class": "risk-matrix"})
    if table is None:
        print("unable to find risk matrix for " + date)
        return None
    # find all the rows in the table
    rows = table.find_all("tr")
    dicts = []
    column_headers = []
    # fetch CVE data from first td in each row
    for row in rows:
        # find the versions in the first row
        header = row.find("th")
        versions = []
        if header is not None:
            component = header.find_next_sibling("th")
            if component.text == "Component":
                score = component.find_next_sibling("th")
                while score.find_next_sibling("th") is not None:
                    versions.append(score.find_next_sibling("th").text)
                    score = score.find_next_sibling("th")
            # extract table column headers
            populate_column_headers(column_headers, header)
            print(column_headers)

        cve = row.find("td")
        affected_major_versions = []
        index = 0
        for column in row.find_all("td"):
            if "•" in column.text:
                affected_major_versions.append(int(column_headers[index]))
            index += 1
        if cve is not None:
            id = cve.text
            if cve.text == "None":
                continue
            link = cve.find("a")["href"]
            componentsTD = cve.find_next_sibling("td")
            component = componentsTD.text.replace("\n", "")
            score_td = componentsTD.find_next_sibling()
            score_text = score_td.text
            affected_versions = intersect_major_versions_with_extracted_affected(
                extracted_affected, affected_major_versions
            )
            parsed_data = {}
            parsed_data["id"] = id
            parsed_data["url"] = link
            parsed_data["date"] = date
            parsed_data["component"] = component
            parsed_data["affected"] = affected_versions
            parsed_data["ojvg_url"] = ojvg_url
            try:
                parsed_data["ojvg_score"] = float(score_text)
            except ValueError:
                print(score_text + " is not a valid score float")
                parsed_data["ojvg_score"] = float("nan")
            print(json.dumps(parsed_data))
            dicts.append(parsed_data)

    return dicts


def dict_to_vulns(dicts: list[dict]) -> list[Vulnerability]:
    vulnerabilities = []
    for parsed_data in dicts:
        affects = BomTarget(ref=parsed_data["component"])
        for v in parsed_data["affected"]:
            # todo: we assume that the affected versions are an intersection between the dots on the grid
            # and the list of all affected versions. This may not necessarily be true, if there are multiple cves
            # one that affects one minor version and another that affects another, within the same major version
            affects.versions.add(v)
        vuln = Vulnerability(
            id=parsed_data["id"],
            source=VulnerabilitySource(
                name="National Vulnerability Database", url=parsed_data["url"]
            ),
            # todo: dummy date
            published=datetime.fromisoformat(parsed_data["date"]),
            updated=datetime.fromisoformat(parsed_data["date"]),
            description="",
            recommendation="",
        )
        vuln.affects.add(affects)
        vr = VulnerabilityRating(
            source=parsed_data["ojvg_url"],
            score=parsed_data["ojvg_score"],
            method=VulnerabilityScoreSource.CVSS_V3_1,
        )
        vuln.ratings.add(vr)
        vulnerabilities.append(vuln)
    return vulnerabilities


"""
We assume the text for the affected versions is in a block like:

"The following vulnerabilities in OpenJDK source code were fixed in this release.
The affected versions are 12, 11.0.2, 8u202, 7u211, and earlier.
We recommend that you upgrade as soon as possible."

"""


def extract_affected(header_string: str) -> list[str]:
    header_string = header_string.replace("\r", "").replace("\n", " ")
    affected = []
    start_vulns = "The affected versions are "
    end_vulns = "Please note that defense-in-depth issues"
    if end_vulns not in header_string:
        end_vulns = "We recommend that you upgrade"  # there is some inconsistency in earlier (2019) formulaic text
    if start_vulns not in header_string or end_vulns not in header_string:
        return []
    vulns_sub = header_string[
        header_string.index(start_vulns)
        + len(start_vulns) : header_string.index(end_vulns)
    ]
    for ver in vulns_sub.split(","):
        ver = ver.strip()
        if "earlier" not in ver:
            affected.append(ver)
    return affected
