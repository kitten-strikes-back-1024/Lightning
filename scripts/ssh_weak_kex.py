import socket

SERVICE = "ssh"
DESCRIPTION = "Check for weak SSH key exchange algorithms"
SCRIPT_NAME = "ssh-weak-kex"

WEAK_KEX = [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1"
]

def run(target, port, args):
    print("[*] SSH weak KEX detection")

    try:
        s = socket.create_connection((target, port), timeout=5)
        s.recv(1024)
        s.sendall(b"SSH-2.0-Lightning\r\n")
        data = s.recv(4096).decode(errors="ignore")

        for algo in WEAK_KEX:
            if algo in data:
                print(f"[+] Weak KEX supported: {algo}")

        s.close()

    except Exception as e:
        print(f"[!] SSH script error: {e}")
