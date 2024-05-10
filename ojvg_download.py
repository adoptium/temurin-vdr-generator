from cvereporter import fetch_vulnerabilities
from datetime import date, timedelta
import json

"""
a brute force ojvg downloader which iterates through all dates from 1 jan 2019 (month reports start) to something close to the present day (end_date).
It downloads all the vulnerability reports as html files to the `data` directory and saves the relevant data in `data/ojvg_summary.json`
"""
start_date = date(2019, 1, 1)
end_date = date(2019, 12, 31)
#end_date = date.today()
current_date = start_date
responses = []
while current_date < end_date:
    date_str = current_date.strftime("%Y-%m-%d")
    print(date_str)
    resp = fetch_vulnerabilities.fetch_dicts(date_str)
    print(resp, flush=True)
    current_date += timedelta(days=1)
    if resp is not None:
        responses.append(resp)

with open("data/openjvg_summary.json", "w") as dump:
    dump.write(json.dumps({"data": responses}, indent=True))
