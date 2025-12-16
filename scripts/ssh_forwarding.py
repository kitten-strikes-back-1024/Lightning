import socket
import paramiko

SERVICE = "ssh"
DESCRIPTION = "Detect SSH port forwarding / tunneling capability"

def run(target, port, args=None):
    print("[*] SSH port forwarding test")

    sock = socket.socket()
    sock.settimeout(5)

    try:
        sock.connect((target, port))
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=5)

        banner = transport.remote_version
        print(f"[+] SSH banner: {banner}")

        try:
            methods = transport.get_security_options().kex
        except:
            methods = None

        # Attempt direct-tcpip channel (forwarding test)
        try:
            transport.open_channel(
                kind="direct-tcpip",
                dest_addr=("127.0.0.1", 22),
                src_addr=("0.0.0.0", 0)
            )
            print("[!] Port forwarding appears ENABLED")
            print("[!] SSH tunneling may expose internal services")

        except paramiko.SSHException:
            print("[-] Port forwarding rejected (likely disabled)")

    except Exception as e:
        print(f"[-] SSH test failed: {e}")

    finally:
        try:
            transport.close()
        except:
            pass
