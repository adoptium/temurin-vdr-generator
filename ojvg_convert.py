import json
import logging
from cvereporter import fetch_vulnerabilities, report, nist_enhance

"""
This file will take a downloaded version of all the CVEs from OJVG which are retrieved by ojvg_download.py and enhance with NIST data, resulting in the creation of the VDR.
"""

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def flatten_file(file) -> list[dict]:
    data = json.load(file)
    flat_list = []
    for big_list in data["data"]:
        for little_list in big_list:
            flat_list.append(little_list)
    return flat_list


with open("data/openjvg_summary.json", "r") as file:
    vulns = fetch_vulnerabilities.dict_to_vulns(flatten_file(file))
    logger.info("parsed and converted %d vulnerabilities from openjvg file", len(vulns))
    bom = report.get_base_bom()
    nist_enhance.enhance(vulns)
    logger.info("nist enhanced %d vulnerabilities", len(vulns))
    for vuln in vulns:
        try:
            bom.vulnerabilities.add(vuln)
        except Exception as e:
            logger.error("failed to add vuln to bom %s due to error: %s", vuln, e)
    with open("data/vdr.json", "w") as vdr:
        vdr.write(report.serialize_to_json(bom))
