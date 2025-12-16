import re
from service_db import SERVICE_DB
from probes import grab_banner, http_probe

def detect_service(target, port):
    if port not in SERVICE_DB:
        return None

    service_info = SERVICE_DB[port]
    response = ""

    if service_info["service"] in ["http", "https"]:
        response = http_probe(target, port)
    else:
        response = grab_banner(target, port)

    response_lower = response.lower()

    best_match = {
        "service": service_info["service"],
        "product": "unknown",
        "version": None,
        "confidence": 0
    }

    for product, fp in service_info["fingerprints"].items():
        for pattern in fp["patterns"]:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else None
                score = fp["score"]

                if score > best_match["confidence"]:
                    best_match.update({
                        "product": product,
                        "version": version,
                        "confidence": score
                    })

    return best_match
