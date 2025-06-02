from cvereporter import fetch_vulnerabilities
from datetime import date, timedelta
import json
import time

"""
a brute force ojvg downloader which iterates through all dates from 1 jan 2019 (month reports start) to something close to the present day (end_date).
It downloads all the vulnerability reports as html files to the `data` directory and saves the relevant data in `data/ojvg_summary.json`
"""
start_date = date(2024, 7, 17)
end_date = date.today()
current_date = start_date
responses = []
# hard code this, to avoid excessive api calls. Assume no backdated advisories will be published, only fetch every day for dates after last report.
list_of_dates = [
    "2024-07-16",
    "2024-04-16",
]
while current_date < end_date:
    date_str = current_date.strftime("%Y-%m-%d")
    current_date += timedelta(days=1)
    list_of_dates.append(date_str)
for date_str in list_of_dates:
    print(date_str)
    resp = fetch_vulnerabilities.fetch_dicts(date_str)
    print(resp, flush=True)
    time.sleep(0.5)  # avoid too many requests per second
    if resp is not None:
        responses.append(resp)

with open("data/openjvg_summary.json", "w") as dump:
    dump.write(json.dumps({"data": responses}, indent=True))
