import socket

SERVICE = "ftp"
DESCRIPTION = "Check for anonymous FTP login"
SCRIPT_NAME = "ftp-anon"


def run(target, port, args):
    print("[*] FTP anonymous login check")

    try:
        s = socket.create_connection((target, port), timeout=5)
        s.recv(1024)

        s.sendall(b"USER anonymous\r\n")
        s.recv(1024)

        s.sendall(b"PASS anonymous\r\n")
        resp = s.recv(1024).decode(errors="ignore")

        if resp.startswith("230"):
            print("[+] Anonymous FTP login ENABLED")
        else:
            print("[-] Anonymous FTP login disabled")

        s.close()

    except Exception as e:
        print(f"[!] FTP script error: {e}")
