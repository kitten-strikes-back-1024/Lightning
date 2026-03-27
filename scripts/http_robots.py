import socket

SERVICE = "http"
DESCRIPTION = "Check for robots.txt"
SCRIPT_NAME = "http-robots"

def run(target, port, args):
    print("[*] robots.txt check")

    try:
        s = socket.create_connection((target, port), timeout=5)

        req = (
            f"GET /robots.txt HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Connection: close\r\n\r\n"
        )

        s.sendall(req.encode())
        resp = s.recv(4096).decode(errors="ignore")

        if "Disallow" in resp:
            print("[+] robots.txt found")
            print(resp.split("\r\n\r\n", 1)[1])
        else:
            print("[-] robots.txt not found or empty")

        s.close()

    except Exception as e:
        print(f"[!] HTTP script error: {e}")
