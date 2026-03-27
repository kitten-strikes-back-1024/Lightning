import socket

SERVICE = "http"
DESCRIPTION = "Check enabled HTTP methods"
SCRIPT_NAME = "http-methods"

def run(target, port, args):
    print("[*] HTTP methods enumeration")

    try:
        s = socket.create_connection((target, port), timeout=5)

        req = (
            f"OPTIONS / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Connection: close\r\n\r\n"
        )

        s.sendall(req.encode())
        resp = s.recv(4096).decode(errors="ignore")

        for line in resp.splitlines():
            if line.lower().startswith("allow:"):
                print(f"[+] Allowed methods: {line.split(':',1)[1].strip()}")

        s.close()

    except Exception as e:
        print(f"[!] HTTP script error: {e}")
