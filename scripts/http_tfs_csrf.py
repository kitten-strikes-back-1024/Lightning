import json

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

SERVICE = "http"
DESCRIPTION = "Taken from TFS(https://github.com/PrathyayPGM-ALT/TFS) with permission. Checks for CSRF vulnerabilities in HTML forms."
SCRIPT_NAME = "http-tfs-csrf"
OPTIONAL = True


def run(target, port, args=None):
    if not REQUESTS_OK:
        print("[!] requests not installed  ->  pip install requests")
        return
    if not BS4_OK:
        print("[!] beautifulsoup4 not installed  ->  pip install beautifulsoup4")
        return

    args = args or {}
    url = args.get("url") or f"http://{target}:{port}"
    output = args.get("output")

    session = requests.Session()
    findings = []

    try:
        resp = session.get(url, allow_redirects=False)
    except Exception as e:
        print(f"[!] Request failed: {e}")
        return

    soup = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")
    print(f"[*] Forms found: {len(forms)}")

    for form in forms:
        action = form.get("action", url)
        method = (form.get("method") or "get").upper()
        inputs = form.find_all("input")
        csrf_tokens = [
            inp for inp in inputs
            if any(k in (inp.get("name") or "").lower()
                   for k in ("csrf", "token", "nonce", "_wpnonce", "authenticity"))
        ]
        has_csrf = bool(csrf_tokens)

        if method == "POST" and not has_csrf:
            findings.append({
                "type": "CSRF",
                "severity": "HIGH",
                "url": url,
                "form_action": action,
                "evidence": "POST form without CSRF token",
            })

    print(f"[*] Findings: {len(findings)}")

    if output:
        with open(output, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"[+] Saved -> {output}")
