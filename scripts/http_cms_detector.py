import requests
from bs4 import BeautifulSoup
SERVICE = "http"
DESCRIPTION = "CMS detection via headers, paths, and HTML fingerprinting"
SCRIPT_NAME = "http-cms-detector"

CMS_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-content/"],
        "html": ["wp-content", "wp-includes"],
        "robots": ["wp-admin"],
        "headers": ["WordPress"]
    },
    "Joomla": {
        "paths": ["/administrator/"],
        "html": ["Joomla!"],
        "robots": ["administrator"]
    },
    "Drupal": {
        "paths": ["/user/login"],
        "html": ["Drupal.settings"],
        "robots": ["drupal"]
    },
    "Gitea": {
        "paths": ["/api/v1/version"],
        "html": ["Gitea"],
    },
    "GitLab": {
        "paths": ["/users/sign_in"],
        "html": ["gitlab"]
    },
    "OpenEMR": {
        "paths": ["/interface/login/login.php", "/setup.php", "/openemr-5_0_1_3"],
        "html": ["OpenEMR", "openemr"],
        "robots": ["interface"],
        "headers": ["OpenEMR"]
    }
}


def run(target, port, args=None):
    base = f"http://{target}:{port}"
    print("[*] CMS detection started")

    try:
        r = requests.get(base, timeout=5)
        headers = str(r.headers)
        html = r.text.lower()
    except Exception as e:
        print(f"[-] HTTP request failed: {e}")
        return

    try:
        robots = requests.get(base + "/robots.txt", timeout=5).text.lower()
    except:
        robots = ""

    for cms, sig in CMS_SIGNATURES.items():
        score = 0

        # Header check
        for h in sig.get("headers", []):
            if h.lower() in headers.lower():
                score += 60

        # Path check
        for path in sig.get("paths", []):
            try:
                resp = requests.head(base + path, timeout=3)
                if resp.status_code < 400:
                    score += 25
            except:
                pass

        # HTML fingerprint
        for marker in sig.get("html", []):
            if marker.lower() in html:
                score += 30

        # robots.txt
        for rbt in sig.get("robots", []):
            if rbt in robots:
                score += 20

        if score > 0:
            score = min(score, 100)
            print(f"[+] CMS Detected: {cms} ({score}% confidence)")
            #finding version
            if cms.lower() == "wordpress":
                print("[*] Finding WordPress version using feed")
                url = base + "/feed"
                try:
                    response = requests.get(url, stream=True)
                    response.raise_for_status()
                    file_content = response.text
                    soup = BeautifulSoup(file_content, "html5lib")
                    wordpressuri = soup.find("generator").text
                    uris = wordpressuri.split("=")
                    uris.remove("https://wordpress.org/?v=")
                    version = uris[0]
                    print(f"\n Version found: Wordpress {version}")
                except:
                    print("[!] Could not find WP version.")
