import psycopg2

SERVICE = "postgres"
DESCRIPTION = "PostgreSQL trust / no-auth access check"
OPTIONAL = True
SCRIPT_NAME = "postgresql-trust"

def run(target, port, args=None):
    try:
        conn = psycopg2.connect(
            host=target,
            port=port,
            user="postgres",
            password="",
            connect_timeout=3
        )
        conn.close()
        print("[+] PostgreSQL allows TRUST / no-password access")
    except:
        print("[-] PostgreSQL requires authentication")
