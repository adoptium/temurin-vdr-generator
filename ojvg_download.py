from cvereporter import fetch_vulnerabilities, fetch_dates
import json
import time
import requests

"""
a brute force ojvg downloader which scrapes the OpenJVG website for all advisory dates
It downloads all the vulnerability reports as html files to the `data` directory and saves the relevant data in `data/ojvg_summary.json`
"""

responses = []

url = "https://openjdk.org/groups/vulnerability/advisories/"
response = requests.get(url)
list_of_dates = fetch_dates.fetch_advisory_dates(response.text)

for date_str in list_of_dates:
    print(date_str)
    resp = fetch_vulnerabilities.fetch_dicts(date_str)
    print(resp, flush=True)
    time.sleep(0.5)  # avoid too many requests per second
    if resp is not None:
        responses.append(resp)

with open("data/openjvg_summary.json", "w") as dump:
    dump.write(json.dumps({"data": responses}, indent=True))
