import re
from service_db import SERVICE_DB
from probes import (
    grab_banner,
    http_probe,
    https_probe,
    smb_probe,
    ftp_probe,
    smtp_probe,
    pop3_probe,
    imap_probe,
    ssh_probe,
    telnet_probe,
    redis_probe,
)

def detect_service(target, port):
    if port not in SERVICE_DB:
        return None

    service_info = SERVICE_DB[port]
    response = ""

    if service_info["service"] == "http":
        response = http_probe(target, port)
    elif service_info["service"] == "https":
        response = https_probe(target, port)
    elif service_info["service"] in ["smb"]:
        response = smb_probe(target,port)
        if port == 445:
            info = smb_probe(target, port)
            if info:
                product = "SMB"
                version = None
                confidence = 70

                os_info = info.get("server_os", "")
                dialect = info.get("dialect")

                if "Samba" in os_info or "Unix" in os_info or "Linux" in os_info:
                    product = "Samba"
                    confidence = 90
                elif "Windows" in os_info:
                    product = "Windows SMB"
                    confidence = 90

                if dialect:
                    version = f"{dialect}"

                return {
                    "service": "smb",
                    "product": product,
                    "version": version,
                    "confidence": confidence,
                }

    elif service_info["service"] == "ftp":
        response = ftp_probe(target, port)
    elif service_info["service"] == "smtp":
        response = smtp_probe(target, port)
    elif service_info["service"] == "pop3":
        response = pop3_probe(target, port)
    elif service_info["service"] == "imap":
        response = imap_probe(target, port)
    elif service_info["service"] == "ssh":
        response = ssh_probe(target, port)
    elif service_info["service"] == "telnet":
        response = telnet_probe(target, port)
    elif service_info["service"] == "redis":
        response = redis_probe(target, port)
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
