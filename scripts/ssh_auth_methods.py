import socket

SERVICE = "ssh"
DESCRIPTION = "Enumerate SSH authentication methods"
SCRIPT_NAME = "ssh-auth-methods"

def run(target, port, args):
    print("[*] SSH authentication methods check")

    try:
        s = socket.create_connection((target, port), timeout=5)
        banner = s.recv(1024)

        # SSH protocol requires client banner first
        s.sendall(b"SSH-2.0-Lightning\r\n")
        data = s.recv(1024).decode(errors="ignore")

        if "password" in data.lower():
            print("[+] Password authentication supported")
        if "publickey" in data.lower():
            print("[+] Public key authentication supported")
        if "keyboard-interactive" in data.lower():
            print("[+] Keyboard-interactive auth supported")

        s.close()

    except Exception as e:
        print(f"[!] SSH script error: {e}")
