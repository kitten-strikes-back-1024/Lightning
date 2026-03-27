import requests

SERVICE = "http"
DESCRIPTION = "Detects possible SQL injection via error-based responses"
OPTIONAL = True
SCRIPT_NAME = "http-sqli"

SQL_ERRORS = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysqli",
        "mysql_fetch"
    ],
    "PostgreSQL": [
        "postgresql",
        "pg_query",
        "pg_fetch",
        "syntax error at or near"
    ],
    "MSSQL": [
        "microsoft sql server",
        "odbc sql server",
        "unclosed quotation mark"
    ],
    "Oracle": [
        "ora-01756",
        "ora-00933",
        "oracle error"
    ],
    "SQLite": [
        "sqlite error",
        "sqliteexception"
    ]
}

PAYLOADS = [
    "'",
    "\"",
    "'--",
    "\"--",
    "')",
    "' OR '1'='1"
]

COMMON_PARAMS = [
    "id", "page", "item", "cat", "user", "uid", "product"
]

def run(target, port, args=None):
    base = f"http://{target}:{port}"
    print("[*] SQL injection detection started")

    for param in COMMON_PARAMS:
        for payload in PAYLOADS:
            url = f"{base}/?{param}={payload}"

            try:
                r = requests.get(url, timeout=5)
                body = r.text.lower()

                for db, errors in SQL_ERRORS.items():
                    for err in errors:
                        if err in body:
                            print(
                                f"[!] Possible SQLi detected "
                                f"(param='{param}', db='{db}', payload='{payload}')"
                            )
                            break
            except:
                continue

    print("[*] SQL injection scan complete")
