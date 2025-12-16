
from serpapi import GoogleSearch
def vulnosint(service, version, apikey):
    query = f"{service} {version} vulnerabilities"
    params = {
        "q": query,
        "engine": "google",
        "api_key": apikey
    }

    search = GoogleSearch(params)
    results = search.get_dict()

    urls = [r["link"] for r in results["organic_results"]]
    return urls