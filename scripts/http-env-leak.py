import requests
import re

SERVICE = "http"
OPTIONAL = True
SCRIPT_NAME = "http-env-leak"
DESCRIPTION = "Detect exposed .env files and extract credentials/secrets"

ENV_PATHS = [
    "/.env",
    "/.env.backup",
    "/.env.local",
    "/.env.prod",
    "/.env.dev",
    "/.env.old",
    "/.env.save",
    "/.env~",
]

# Keys worth reporting (you can extend this)
SENSITIVE_KEYS = [
    "DB_PASS", "DB_PASSWORD",
    "MYSQL_PASSWORD", "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
    "SECRET_KEY", "APP_KEY",
    "AWS_SECRET", "AWS_ACCESS_KEY",
    "JWT_SECRET", "TOKEN"
]

KEY_VALUE_RE = re.compile(r'^([A-Z0-9_]+)\s*=\s*(.+)$')


def run(target, port, args):
    base = f"http://{target}:{port}"
    headers = {
        "User-Agent": "Mozilla/5.0 LightningScanner/1.0"
    }

    for path in ENV_PATHS:
        url = base + path
        try:
            r = requests.get(url, headers=headers, timeout=5)

            if r.status_code != 200:
                continue

            text = r.text.strip()

            # Quick sanity check: real .env files always have KEY=VALUE
            if "=" not in text or len(text) < 20:
                continue

            print(f"[CRITICAL] Exposed .env file found: {url}")

            secrets_found = False

            for line in text.splitlines():
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                match = KEY_VALUE_RE.match(line)
                if not match:
                    continue

                key, value = match.groups()

                for sensitive in SENSITIVE_KEYS:
                    if sensitive in key:
                        secrets_found = True
                        masked = mask_secret(value)
                        print(f"    {key} = {masked}")

            if not secrets_found:
                print("    [!] No high-value secrets detected (still sensitive!)")

        except requests.RequestException:
            continue


def mask_secret(value):
    """
    Mask secrets but keep them identifiable
    """
    value = value.strip().strip('"').strip("'")
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]
