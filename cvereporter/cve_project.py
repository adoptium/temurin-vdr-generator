import json
import logging
from typing import Any, Optional

import requests

"""
this file has the utilities for downloading individual cve records from the CVE Project's cvelistV5 repository
(https://github.com/CVEProject/cvelistV5) and extracting the parts relevant to the vdr
"""

logger = logging.getLogger(__name__)

CVE_PROJECT_RAW_BASE = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
)
CVE_PROJECT_BLOB_BASE = "https://github.com/CVEProject/cvelistV5/blob/main/cves"


def cve_project_path(id: str) -> str:
    # records are laid out as cves/<year>/<number with the last 3 digits replaced by xxx>/<id>.json
    # e.g. CVE-2026-22016 -> cves/2026/22xxx/CVE-2026-22016.json
    _, year, number = id.split("-")
    bucket = str(int(number) // 1000) + "xxx"
    return f"{year}/{bucket}/{id}.json"


def cve_project_url(id: str) -> str:
    # static file download url, used to fetch the record
    return f"{CVE_PROJECT_RAW_BASE}/{cve_project_path(id)}"


def cve_project_record_url(id: str) -> str:
    # human readable url of the same record, used for provenance in the vdr
    return f"{CVE_PROJECT_BLOB_BASE}/{cve_project_path(id)}"


def fetch_cve_project(id: str) -> Optional[dict]:
    file_location = "data/cveproject_" + id + ".json"
    try:
        with open(file_location, "r") as the_file:
            data = json.load(the_file)["data"]
            logger.debug("resolved from cache %s", id)
            return data
    except (OSError, ValueError, KeyError):
        logger.debug(
            "unable to find pre-fetched cve project record, actually performing fetch."
        )
    try:
        url = cve_project_url(id)
    except ValueError:
        logger.error("unable to build cve project url for id %s", id)
        return None
    logger.info("making call to cve project: %s", url)
    try:
        resp = requests.get(url, timeout=30)
    except requests.RequestException as e:
        logger.error("error fetching %s from cve project: %s", id, e)
        return None
    if resp.status_code != 200:
        logger.warning(
            "error fetching %s from cve project; status code: %s", id, resp.status_code
        )
        return None
    try:
        data = resp.json()
    except ValueError as e:
        logger.error("error parsing cve project response for %s: %s", id, e)
        return None
    with open(file_location, "w") as dest:
        json.dump({"url": url, "data": data}, dest, indent=2)
    return data


def extract_relevant_parts(record: dict) -> dict:
    """
    builds the same shape of dict as nist_enhance.extract_relevant_parts, so the two sources are interchangeable
    """
    resp_dict: dict[str, Any] = {}
    containers = record["containers"]
    cna = containers["cna"]

    description = ""
    for desc in cna.get("descriptions", []):
        # the cve project uses BCP 47 tags such as "en" or "en-US"
        if desc["lang"].lower().startswith("en"):
            description = desc["value"]
            break

    ratings = []
    # the cna (e.g. oracle) supplies the primary scores; adp containers (e.g. CISA) may add their own
    for container in [cna] + containers.get("adp", []):
        source = container.get("providerMetadata", {}).get("shortName", "")
        metrics_list = container.get("metrics", [])
        # older records (e.g. oracle's 2020 cves) only have cvss 3.0; use those if there's no 3.1 score
        key = "cvssV3_1"
        if not any(key in metrics for metrics in metrics_list):
            key = "cvssV3_0"
        for metrics in metrics_list:
            cvss = metrics.get(key)
            if not cvss:
                continue
            relevant = {}
            relevant["source"] = source
            relevant["score"] = cvss["baseScore"]
            relevant["severity"] = cvss["baseSeverity"]
            relevant["method"] = "CVSSv3"
            relevant["vector"] = cvss["vectorString"]
            ratings.append(relevant)

    resp_dict["ratings"] = ratings
    resp_dict["description"] = description
    resp_dict["versions"] = extract_versions(cna.get("affected", []))
    return resp_dict


def extract_versions(affected: list[dict]) -> list[str]:
    vers = []
    oracle_jdk_start = "Oracle Java SE:"  # todo: do we care about non oracle
    for product in affected:
        for version in product.get("versions", []):
            ver = version.get("version", "")
            if version.get("status") == "affected" and ver.startswith(oracle_jdk_start):
                vers.append(ver[len(oracle_jdk_start) :])
    return vers
