import json
from cve_pipeline import fetch_vulnerabilities, report, nist_enhance

"""
This file will take a downloaded version of all the CVEs from OJVG which are retrieved by ojvg_download.py and enhance with NIST data, resulting in the creation of the VDR.
"""

def flatten_file(file) -> list[dict]:
    data = json.load(file)
    flat_list = []
    for big_list in data["data"]:
        for little_list in big_list:
            flat_list.append(little_list)
    return flat_list
with open("data/openjvg_summary.json", "r") as file:
    vulns = fetch_vulnerabilities.dict_to_vulns(flatten_file(file))
    print("parsed and converted {} vulnerabilities from openjvg file".format(len(vulns)))
    bom = report.get_base_bom()
    nist_enhance.enhance(vulns)
    print("nist enhanced {} vulnerabilities".format(len(vulns)))
    for vuln in vulns:
        bom.vulnerabilities.add(vuln)
    with open("data/vdr.json", "w") as vdr:
        vdr.write(report.serialize_to_json(bom))