import socket

SERVICE = "http"
DESCRIPTION = "Check common HTTP security headers"
SCRIPT_NAME = "http-headers"

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security"
]

def run(target, port, args):
    print("[*] HTTP security headers check")

    try:
        s = socket.create_connection((target, port), timeout=5)

        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: Lightning\r\n"
            f"Connection: close\r\n\r\n"
        )

        s.sendall(req.encode())
        data = s.recv(8192).decode(errors="ignore")
        headers = data.split("\r\n\r\n")[0]

        for h in SECURITY_HEADERS:
            if h.lower() in headers.lower():
                print(f"[+] {h}: PRESENT")
            else:
                print(f"[-] {h}: MISSING")

        s.close()

    except Exception as e:
        print(f"[!] HTTP script error: {e}")
