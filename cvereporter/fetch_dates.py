from datetime import date

from bs4 import BeautifulSoup


""" Fetches a list of advisory dates from the OpenJVG website."""

def fetch_advisory_dates(data):
    soup = BeautifulSoup(data, "html.parser")  
    dates = []
    for link in soup.find_all("a"):
        href = link.get("href")
        # Check if the link is an advisory link, date links are in the format YYYY-MM-DD
        try: 
            date_str = str(href)
            date.fromisoformat(href)
            dates.append(date_str)
        except ValueError:
            # If the link is not a valid date, skip it
            continue
    return dates
