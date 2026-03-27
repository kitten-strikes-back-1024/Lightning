import socket

SERVICE = "ftp"
DESCRIPTION = "Check FTP response behavior for user enumeration"
SCRIPT_NAME = "ftp-bruteforce-check"


def run(target, port, args):
    print("[*] FTP user enumeration check")

    try:
        s = socket.create_connection((target, port), timeout=5)
        s.recv(1024)

        s.sendall(b"USER root\r\n")
        resp1 = s.recv(1024).decode(errors="ignore")

        s.sendall(b"USER nosuchuser\r\n")
        resp2 = s.recv(1024).decode(errors="ignore")

        if resp1 != resp2:
            print("[+] Possible FTP user enumeration detected")
        else:
            print("[-] FTP user enumeration unlikely")

        s.close()

    except Exception as e:
        print(f"[!] FTP script error: {e}")
