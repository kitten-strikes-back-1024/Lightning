import socket

SERVICE = "http"
DESCRIPTION = "Check common admin paths"
SCRIPT_NAME = "http-admin-paths"
PATHS = [
    "/admin",
    "/administrator",
    "/login",
    "/wp-admin",
    "/phpmyadmin"
]

def run(target, port, args):
    print("[*] Common admin path check")

    for path in PATHS:
        try:
            s = socket.create_connection((target, port), timeout=3)

            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Connection: close\r\n\r\n"
            )

            s.sendall(req.encode())
            resp = s.recv(2048).decode(errors="ignore")

            if "200 OK" in resp or "302 Found" in resp:
                print(f"[+] Possible admin page: {path}")

            s.close()

        except Exception:
            continue
