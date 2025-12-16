import re, requests

def discover_cpes(service, nvdapikey):
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={service}"
    )
    headers = {"apiKey": nvdapikey}
    r = requests.get(url, headers=headers)
    data = r.json()

    cpes = set()

    for v in data.get("vulnerabilities", []):
        configs = v.get("cve", {}).get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria")
                    if cpe and ":a:" in cpe:
                        cpes.add(cpe)

    return list(cpes)
def filter_cpes_by_version(cpes, version):
    return [
        cpe for cpe in cpes
        if f":{version}:" in cpe or cpe.endswith(":*:*:*:*:*:*:*:*")
    ]
def nvd_search(service, version, nvdapikey):
    cpes = discover_cpes(service, nvdapikey)
    results = {}

    for cpe in cpes:
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?cpeName={cpe}"
        )
        headers = {"apiKey": nvdapikey}
        r = requests.get(url, headers=headers)

        if r.status_code != 200:
            continue

        try:
            data = r.json()
        except ValueError:
            continue

        for v in data.get("vulnerabilities", []):
            cve = v["cve"]["id"]
            for d in v["cve"]["descriptions"]:
                if d["lang"] == "en":
                    results[cve] = d["value"]
                    break

    return results
