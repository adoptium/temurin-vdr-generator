import collections
import decimal
import enum
import logging
from typing import Any, Callable, Optional
from cyclonedx.model.vulnerability import (
    Vulnerability,
    VulnerabilitySource,
    VulnerabilityScoreSource,
    VulnerabilityRating,
    BomTarget,
    BomTargetVersionRange,
)
from cyclonedx.model import XsUri
import requests
import json
import time
import os
from cvereporter import cve_project

"""
this file has the utilities for downloading data about cves from NIST and updating Vulnerability objects with the data
"""

logger = logging.getLogger(__name__)


class DataSourceMode(enum.Enum):
    NVD_ONLY = "nvd_only"
    # falls back to the nvd if the cve project has no file for the cve, or its file has no ratings
    CVE_PROJECT_THEN_NVD = "cve_project_then_nvd"
    # falls back to the nvd only if the cve project has no file for the cve (fastest, fewest nvd calls)
    CVE_PROJECT_THEN_NVD_IF_MISSING = "cve_project_then_nvd_if_missing"
    NVD_THEN_CVE_PROJECT = "nvd_then_cve_project"


# where cve descriptions and ratings come from, and in which order the sources are tried, is selected with the
# VDR_DATA_SOURCE_MODE environment variable, set to one of the DataSourceMode values. this is used if it isn't set.
DEFAULT_DATA_SOURCE_MODE = DataSourceMode.NVD_ONLY
DATA_SOURCE_MODE_ENV = "VDR_DATA_SOURCE_MODE"


def mode_from_env() -> DataSourceMode:
    value = os.environ.get(DATA_SOURCE_MODE_ENV, "").strip()
    if not value:
        return DEFAULT_DATA_SOURCE_MODE
    try:
        return DataSourceMode(value)
    except ValueError:
        valid = ", ".join(m.value for m in DataSourceMode)
        raise ValueError(
            f"invalid {DATA_SOURCE_MODE_ENV} '{value}', expected one of: {valid}"
        )


def fetch_nist(url: str, id: str) -> Optional[dict]:
    file_location = "data/nist_" + id + ".json"
    try:
        with open(file_location, "r") as the_file:
            data = json.load(the_file)["data"]
            logger.debug("resolved from cache %s", url)
            return data
    except:
        logger.debug(
            "unable to find pre-fetched nist response, actually performing fetch."
        )
    data = None
    nist_resp = None
    headers = {}
    if (
        "NIST_NVD_TOKEN" in os.environ and os.environ["NIST_NVD_TOKEN"]
    ):  # check not empty
        logger.info("making call to NIST using api key: %s", url)
        delay = 1  # stay well within 50 requests/30 seconds
        headers["apiKey"] = os.environ["NIST_NVD_TOKEN"]
    else:
        logger.info("making call to NIST without api key: %s", url)
        delay = 10  # stay well within 5 requests/30 seconds
    # retry connection errors, timeouts, rate limiting and server errors (e.g. the nvd returning 503 or closing the
    # connection), so one blip doesn't fail the run or silently drop a cve
    attempts = 3
    for attempt in range(1, attempts + 1):
        # back off further on each retry
        time.sleep(delay if attempt == 1 else 10 * attempt)
        try:
            nist_resp = requests.get(url, headers=headers, timeout=60)
        except requests.RequestException as e:
            logger.warning(
                "error fetching %s from NIST (attempt %s of %s): %s",
                id,
                attempt,
                attempts,
                e,
            )
            continue
        if nist_resp.status_code == 429 or nist_resp.status_code >= 500:
            logger.warning(
                "error fetching %s from NIST (attempt %s of %s): status code %s",
                id,
                attempt,
                attempts,
                nist_resp.status_code,
            )
            continue
        break
    if nist_resp is None:
        logger.error("giving up fetching %s from NIST", id)
        return None
    if nist_resp.status_code != 200:
        logger.error(
            "error fetching %s; status code: %s; text: %s",
            id,
            nist_resp.status_code,
            nist_resp.text,
        )
        """
            the most frequently seen error response is:
            error fetching CVE-2020-2805; status code: 403; text: <html><body><h1>403 Forbidden</h1> Request forbidden by administrative rules.
        """
    else:
        data = nist_resp.json()
        with open(file_location, "w") as dest:
            json.dump({"url": url, "data": data}, dest, indent=True)
    return data


def extract_relevant_parts(nist_resp: dict) -> dict:
    # todo: this can use a unit test at some point
    resp_dict: dict[str, Any] = {}
    ratings = []
    cve = nist_resp["vulnerabilities"][0]["cve"]
    # todo: do we have more than 1 cve in a resp?
    description = ""
    for desc in cve["descriptions"]:
        if desc["lang"] == "en":
            description = desc["value"]

    # cves that nvd hasn't analysed yet may have no metrics or configurations; keep the description anyway
    for metrics in cve.get("metrics", {}).get("cvssMetricV31", []):
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
    resp_dict["versions"] = extract_versions(cve.get("configurations", []))
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


def cvss_method(vector: str) -> VulnerabilityScoreSource:
    # cvss 3.0 scores come from older cve project records, everything else we read is 3.1
    if vector.startswith("CVSS:3.0/"):
        return VulnerabilityScoreSource.CVSS_V3
    return VulnerabilityScoreSource.CVSS_V3_1


def relevant_from_nvd(id: str) -> Optional[dict]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + id
    nist_resp = fetch_nist(url, id)
    if nist_resp is None:
        return None
    try:
        return extract_relevant_parts(nist_resp)
    except (KeyError, IndexError):
        logger.warning("unable to extract relevant parts of nvd response for %s", id)
        return None


def relevant_from_cve_project(id: str) -> Optional[dict]:
    record = cve_project.fetch_cve_project(id)
    if record is None:
        return None
    try:
        return cve_project.extract_relevant_parts(record)
    except KeyError:
        logger.warning(
            "unable to extract relevant parts of cve project record for %s", id
        )
        return None


NVD = "nvd"
CVE_PROJECT = "cve_project"

# names and record urls used to record the provenance of the data in the vdr
SOURCE_NAMES = {
    NVD: "National Vulnerability Database",
    CVE_PROJECT: "CVE Project (cvelistV5)",
}


def nvd_record_url(id: str) -> str:
    return "https://nvd.nist.gov/vuln/detail/" + id


def record_url(data_source: str, id: str) -> str:
    if data_source == CVE_PROJECT:
        return cve_project.cve_project_record_url(id)
    return nvd_record_url(id)


def get_sources(
    mode: DataSourceMode,
) -> list[tuple[str, Callable[[str], Optional[dict]]]]:
    nvd = (NVD, relevant_from_nvd)
    cve = (CVE_PROJECT, relevant_from_cve_project)
    if mode == DataSourceMode.NVD_ONLY:
        return [nvd]
    if mode in (
        DataSourceMode.CVE_PROJECT_THEN_NVD,
        DataSourceMode.CVE_PROJECT_THEN_NVD_IF_MISSING,
    ):
        return [cve, nvd]
    return [nvd, cve]


def get_relevant(id: str, mode: DataSourceMode) -> Optional[dict]:
    """
    tries each source in order, moving on to the next one if a source has no record or the record has no ratings
    (or only if it has no record, for CVE_PROJECT_THEN_NVD_IF_MISSING).
    if no source has ratings, the first record found is used so we at least get a description.
    the name of the source used is recorded under "data_source".
    """
    first_found = None
    for name, source in get_sources(mode):
        relevant = source(id)
        if relevant is None:
            continue
        relevant["data_source"] = name
        if (
            relevant["ratings"]
            or mode == DataSourceMode.CVE_PROJECT_THEN_NVD_IF_MISSING
        ):
            return relevant
        logger.info("%s returned no ratings for %s, trying next source", name, id)
        if first_found is None:
            first_found = relevant
    return first_found


def enhance(
    vulns: list[Vulnerability], mode: Optional[DataSourceMode] = None
) -> collections.Counter:
    if mode is None:
        mode = mode_from_env()
    logger.info("enhancing vulnerabilities using data source mode: %s", mode.value)
    # counts which source supplied the data used for each vuln (whether fetched or read from cache)
    summary: collections.Counter = collections.Counter()
    count = 0
    for vuln in vulns:
        count += 1
        id = vuln.id
        if not id:
            summary["not found"] += 1
            continue
        relevant = get_relevant(id, mode)
        if relevant is None:
            logger.warning("no data found for %s in any source", id)
            summary["not found"] += 1
            continue
        if relevant["ratings"]:
            summary[relevant["data_source"]] += 1
        else:
            summary["description only (" + relevant["data_source"] + ")"] += 1
        logger.debug("enhancing vuln: %s (index %s)", id, count)
        # the vuln's source is the database we actually took the description and ratings from
        url = XsUri(record_url(relevant["data_source"], id))
        vuln.source = VulnerabilitySource(
            name=SOURCE_NAMES[relevant["data_source"]], url=url
        )
        # print(json.dumps(relevant, indent=True))
        for rating in relevant["ratings"]:

            score_float = float("nan")
            try:
                score_float = float(rating["score"])
            except ValueError:
                logger.warning("%s is not a float", str(rating["score"]))
            # todo: convert the ratings into the cyclonedx enums?
            vr = VulnerabilityRating(
                # name is who scored it (e.g. oracle, nvd@nist.gov), url is the record we read the score from
                source=VulnerabilitySource(name=rating["source"], url=url),
                score=decimal.Decimal(rating["score"]),
                vector=rating["vector"],
                method=cvss_method(rating["vector"]),
            )
            try:
                vuln.ratings.add(vr)
            except Exception as e:
                logger.error("error adding rating: %s due to error: %s", vr, e)
        vuln.description = relevant["description"]
        # for now - we use versions we extract when we download from OpenJDK Vulnerability group
        # this version extraction is tied to the Oracle JDKs which might not map directly to openjdk versions
        # that approach also has limitations: we have to do a bit of guesswork mapping cves to versions
        extract_versions_from_nist = False
        if extract_versions_from_nist:
            for affects in vuln.affects:
                for ver in relevant["versions"]:
                    affects.versions.add(BomTargetVersionRange(version=ver))
        # print(vuln)
    log_summary(summary, mode, len(vulns))
    return summary


def log_summary(summary: collections.Counter, mode: DataSourceMode, total: int):
    logger.info(
        "data source summary (mode %s): %d vulns, %s",
        mode.value,
        total,
        ", ".join(name + "=" + str(n) for name, n in sorted(summary.items())),
    )
