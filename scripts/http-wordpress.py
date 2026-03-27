import requests
import re
from bs4 import BeautifulSoup

SERVICE = "http"
OPTIONAL = True
SCRIPT_NAME = "http-wordpress"
DESCRIPTION = "WordPress detection, versioning, plugin/theme discovery"

HEADERS = {
    "User-Agent": "Mozilla/5.0 LightningScanner/1.0"
}

COMMON_PLUGINS = [
    "woocommerce",
    "elementor",
    "contact-form-7",
    "wpforms",
    "yoast-seo",
    "wordfence",
    "all-in-one-seo-pack",
]

COMMON_THEMES = [
    "astra",
    "twentytwentythree",
    "twentytwentytwo",
    "twentytwentyone",
    "generatepress",
]

def run(target, port, args):
    base = f"http://{target}:{port}"

    try:
        r = requests.get(base, headers=HEADERS, timeout=5)
    except Exception:
        return

    html = r.text.lower()
    headers = r.headers

    if not is_wordpress(html, headers):
        return

    print("[+] WordPress detected")

    version = detect_version(base, html)
    if version:
        print(f"[+] WordPress version: {version}")
        if is_outdated(version):
            print("[!] WordPress version appears outdated")

    plugins = detect_plugins(html)
    if plugins:
        print("[+] Plugins detected:")
        for p in plugins:
            print(f"    - {p}")

    themes = detect_themes(html)
    if themes:
        print("[+] Themes detected:")
        for t in themes:
            print(f"    - {t}")

    check_xmlrpc(base)
    check_user_enum(base)


# ----------------------------
# Detection helpers
# ----------------------------

def is_wordpress(html, headers):
    if "wp-content" in html or "wp-includes" in html:
        return True
    if "x-powered-by" in headers and "wordpress" in headers["x-powered-by"].lower():
        return True
    return False


def detect_version(base, html):
    # 1️⃣ Meta generator
    match = re.search(r'wordpress\s+([\d\.]+)', html)
    if match:
        return match.group(1)

    # 2️⃣ RSS feed
    try:
        r = requests.get(base + "/feed", headers=HEADERS, timeout=5)
        soup = BeautifulSoup(r.content, "xml")
        gen = soup.find("generator")
        if gen and "?v=" in gen.text:
            return gen.text.split("?v=")[-1]
    except Exception:
        pass

    # 3️⃣ readme.html (high confidence)
    try:
        r = requests.get(base + "/readme.html", headers=HEADERS, timeout=5)
        if r.status_code == 200:
            match = re.search(r"Version\s+([\d\.]+)", r.text)
            if match:
                print("[!] readme.html exposed")
                return match.group(1)
    except Exception:
        pass

    return None


def detect_plugins(html):
    found = set()
    for p in COMMON_PLUGINS:
        if f"/wp-content/plugins/{p}" in html:
            found.add(p)
    return sorted(found)


def detect_themes(html):
    found = set()
    for t in COMMON_THEMES:
        if f"/wp-content/themes/{t}" in html:
            found.add(t)
    return sorted(found)


def check_xmlrpc(base):
    try:
        r = requests.post(base + "/xmlrpc.php", timeout=5)
        if r.status_code == 200:
            print("[!] xmlrpc.php enabled (bruteforce / pingback risk)")
    except Exception:
        pass


def check_user_enum(base):
    try:
        r = requests.get(base + "/?author=1", allow_redirects=True, timeout=5)
        if "/author/" in r.url:
            print("[!] User enumeration possible via ?author=")
    except Exception:
        pass


def is_outdated(version):
    try:
        major = int(version.split(".")[0])
        return major < 6
    except Exception:
        return False
