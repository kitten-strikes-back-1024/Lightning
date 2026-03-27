from exploitdb_csv import build_cve_index, search_by_product_version


def fetch_csv_descriptions(cves):
    index = build_cve_index()
    results = {}
    for cve in cves:
        results[cve] = index.get(cve)
    return results


def vulnsearch(service, version):
    results = search_by_product_version(service, version)
    cves = list(results.keys())
    descs = fetch_csv_descriptions(cves=cves)
    return cves, descs
