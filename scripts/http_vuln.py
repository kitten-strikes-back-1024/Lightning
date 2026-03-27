import requests
import urllib.parse

SERVICE = "http"
DESCRIPTION = "Detects basic web vulns: reflected XSS, open redirect, SSRF hints, dangerous methods"
OPTIONAL = True
SCRIPT_NAME = "http-vuln"

SAFE_MARKER = "LIGHTNING_TEST"

COMMON_PARAMS = [
    "q", "search", "s", "id", "page", "url", "next", "redirect", "return"
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
]

def run(target, port, args=None):
    base = f"http://{target}:{port}"
    print("[*] HTTP vulnerability scan started")

    try:
        r = requests.get(base, timeout=5)
    except Exception:
        print("[-] Site unreachable")
        return


    print("\n[*] Security headers:")
    for h in SECURITY_HEADERS:
        if h not in r.headers:
            print(f"[-] Missing header: {h}")
        else:
            print(f"[+] {h} present")


    try:
        opt = requests.options(base, timeout=5)
        allow = opt.headers.get("Allow", "")
        if allow:
            bad = [m for m in ["PUT", "DELETE", "TRACE"] if m in allow]
            if bad:
                print(f"\n[!] Dangerous HTTP methods enabled: {', '.join(bad)}")
            else:
                print("\n[+] No dangerous HTTP methods exposed")
    except:
        pass

    print("\n[*] Reflected XSS check:")
    for param in COMMON_PARAMS:
        payload = SAFE_MARKER
        url = f"{base}/?{param}={payload}"

        try:
            resp = requests.get(url, timeout=5)
            if payload in resp.text:
                print(f"[!] Possible reflected XSS via parameter: {param}")
        except:
            pass

    print("\n[*] Open redirect check:")
    test_url = "https://example.com"
    for param in ["next", "url", "redirect", "return"]:
        q = urllib.parse.quote(test_url)
        url = f"{base}/?{param}={q}"

        try:
            resp = requests.get(url, allow_redirects=False, timeout=5)
            loc = resp.headers.get("Location", "")
            if test_url in loc:
                print(f"[!] Open redirect via parameter: {param}")
        except:
            pass


    print("\n[*] SSRF indicators:")
    for param in ["url", "dest", "redirect", "callback"]:
        url = f"{base}/?{param}=http://127.0.0.1"

        try:
            resp = requests.get(url, timeout=5)
            if any(x in resp.text.lower() for x in ["connection refused", "localhost", "127.0.0.1"]):
                print(f"[!] Possible SSRF behavior on parameter: {param}")
        except:
            pass

    print("\n[*] HTTP vuln scan complete")
