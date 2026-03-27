from exploitdb_csv import search_by_product_version


def csv_search(service, version, limit=None):
    return search_by_product_version(service, version, limit=limit)
