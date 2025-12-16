def http_probe(target, port):
    import socket
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        req = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"
        s.send(req.encode())
        data = s.recv(4096).decode(errors="ignore")
        s.close()
        return data
    except:
        return ""
def grab_banner(target, port):
    import socket
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(2048).decode(errors="ignore")
        s.close()
        return banner
    except:
        return ""
