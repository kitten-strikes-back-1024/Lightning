from serpapi import GoogleSearch
import re
import requests
from bs4 import BeautifulSoup

def vulnosint(service, version, apikey):
    query = f"{service} {version} vulnerabilities exploitdb"
    params = {
        "q": query,
        "engine": "google",
        "api_key": apikey
    }

    search = GoogleSearch(params)
    results = search.get_dict()

    urls = [r["link"] for r in results["organic_results"]]
    return urls
def extract_cves_from_exploitdb(urls):
    cves = set()
    cve_regex = re.compile(r"CVE-\d{4}-\d{4,7}")

    for url in urls:
        try:
            r = requests.get(url, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")

            meta = soup.find("meta", attrs={"name": "keywords"})
            if not meta or "content" not in meta.attrs:
                continue

            keywords = meta["content"].split(",")
            for k in keywords:
                match = cve_regex.search(k)
                if match:
                    cves.add(match.group())

        except Exception:
            continue

    return list(cves)
def fetch_nvd_descriptions(cves, nvdapikey):
    results = {}
    headers = {"apiKey": nvdapikey}
    for cve in cves:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

        r = requests.get(url,headers=headers)
        data = r.json()

        try:
            descs = data["vulnerabilities"][0]["cve"]["descriptions"]
            for d in descs:
                if d["lang"] == "en":
                    results[cve] = d["value"]
                    break
        except (KeyError, IndexError):
            results[cve] = None

    return list(results)
def vulnsearch(service, version, apikey, nvdapikey):
    urls = vulnosint(service=service, version=version, apikey=apikey)
    cves = extract_cves_from_exploitdb(urls=urls)
    descs = fetch_nvd_descriptions(cves=cves, nvdapikey=nvdapikey)
    return cves, descs