#!/usr/bin/env python3

import argparse
import json
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from cyclonedx.model.impact_analysis import ImpactAnalysisAffectedStatus
from cyclonedx.model.vulnerability import (
    Vulnerability,
    VulnerabilitySource,
    VulnerabilityScoreSource,
    VulnerabilityRating,
    VulnerabilitySeverity,
    BomTarget,
    BomTargetVersionRange,
)

"""
Utilities to fetch data from OJVG and convert it to intermediate representations/CycloneDX structure
"""


def fetch_cves(date: str) -> list[Vulnerability]:
    return dict_to_vulns(fetch_dicts(date))


def fetch_dicts(date: str):
    cve_text = retrieve_cves_from_internet(date)
    dicts = parse_to_dict(cve_text, date)
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
        print(r)
    except requests.exceptions.ReadTimeout:
        return None
    if r.status_code == 404:
        return None
    resp_text = r.text
    # todo: make this configurable
    with open("data/open_jvg_dump_" + date + ".html", "w") as dump:
        dump.write(resp_text)
    return resp_text


def parse_to_cyclone(resp_text: str, date: str) -> list[Vulnerability]:
    dicts = parse_to_dict(resp_text, date)
    return dict_to_vulns(dicts)


def parse_to_dict(resp_text: str, date: str) -> list[dict]:
    if resp_text is None:
        return None
    soup = BeautifulSoup(resp_text, "html.parser")

    # find the versions affected
    header_string = soup.find(name="p")
    extracted_affected = extract_affected(header_string.text)

    # find the table with the CVEs
    table = soup.find("table", attrs={"class": "risk-matrix"})

    # find all the rows in the table
    rows = table.find_all("tr")
    dicts = []
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

        cve = row.find("td")
        if cve is not None:
            id = cve.text
            if cve.text == "None":
                continue
            link = cve.find("a")["href"]
            componentsTD = cve.find_next_sibling("td")
            component = componentsTD.text.replace("\n", "")
            scoreTD = componentsTD.find_next_sibling("td")
            score = scoreTD.text

            versionCheck = scoreTD
            affected_versions = []
            affected_versions += (
                extracted_affected  # todo - maybe just the extracted ones
            )
            for version in versions:
                versionCheck = versionCheck.find_next_sibling("td")
                if versionCheck.text == "•":
                    affected_versions.append(int(version))

            parsed_data = {}
            parsed_data["id"] = id
            parsed_data["url"] = link
            parsed_data["date"] = date
            parsed_data["component"] = component
            parsed_data["affected"] = affected_versions
            print(json.dumps(parsed_data))
            dicts.append(parsed_data)

    return dicts


def dict_to_vulns(dicts: list[dict]) -> list[Vulnerability]:
    vulnerabilities = []
    for parsed_data in dicts:
        affects = BomTarget(ref=parsed_data["component"])
        # for v in parsed_data["affected"]:
        # todo: this is not actually true - the affected versions are just for the whole report
        # we need to extract affected versions on a per cve basis, not a per ojvg report basis
        # affects.versions.add(v)
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
        vulnerabilities.append(vuln)
        # print(vuln)
    return vulnerabilities


def extract_affected(header_string: str) -> list[str]:
    header_string = header_string.replace("\r", "").replace("\n", " ")
    # print(header_string)
    affected = []
    start_vulns = "The affected versions are "
    end_vulns = "Please note that defense-in-depth issues"
    if start_vulns not in header_string or end_vulns not in header_string:
        return []
    vulns_sub = header_string[
        header_string.index(start_vulns)
        + len(start_vulns) : header_string.index(end_vulns)
    ]
    # print(vulns_sub)
    for ver in vulns_sub.split(","):
        ver = ver.strip()
        if "earlier" not in ver:
            affected.append(ver)
    # print(affected)
    return affected


# fetch_cves('2023-01-17')
