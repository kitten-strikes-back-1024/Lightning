import socket

SERVICE = "redis"
DESCRIPTION = "Redis unauth access & INFO dump"
SCRIPT_NAME = "redis-info-dump"

def run(target, port, args=None):
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((target, port))

        s.send(b"*1\r\n$4\r\nPING\r\n")
        resp = s.recv(1024)

        if b"PONG" not in resp:
            print("[-] Redis requires authentication")
            return

        print("[+] Redis allows anonymous access")

        s.send(b"*1\r\n$4\r\nINFO\r\n")
        info = s.recv(4096).decode(errors="ignore")

        for line in info.splitlines():
            if any(k in line for k in ["redis_version", "os:", "arch_bits", "tcp_port"]):
                print(f"    {line}")

        s.close()

    except:
        print("[-] Redis connection failed")
