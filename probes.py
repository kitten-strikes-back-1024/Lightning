import socket
import ssl


def http_probe(target, port, path="/"):

    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        req = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        s.send(req.encode())
        data = s.recv(4096).decode(errors="ignore")
        s.close()
        return data
    except:
        return ""


def https_probe(target, port, path="/"):
    try:
        context = ssl.create_default_context()
        s = socket.socket()
        s.settimeout(3)
        s.connect((target, port))
        tls = context.wrap_socket(s, server_hostname=target)
        req = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        tls.send(req.encode())
        data = tls.recv(4096).decode(errors="ignore")
        tls.close()
        return data
    except:
        return ""


def ftp_probe(target, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(2048).decode(errors="ignore")
        s.send(b"FEAT\r\n")
        feat = s.recv(2048).decode(errors="ignore")
        s.close()
        return banner + "\n" + feat
    except:
        return ""


def smtp_probe(target, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(2048).decode(errors="ignore")
        s.send(b"EHLO lightning\r\n")
        ehlo = s.recv(2048).decode(errors="ignore")
        s.close()
        return banner + "\n" + ehlo
    except:
        return ""


def pop3_probe(target, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(2048).decode(errors="ignore")
        s.send(b"CAPA\r\n")
        capa = s.recv(2048).decode(errors="ignore")
        s.close()
        return banner + "\n" + capa
    except:
        return ""


def imap_probe(target, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(2048).decode(errors="ignore")
        s.send(b"a001 CAPABILITY\r\n")
        capa = s.recv(2048).decode(errors="ignore")
        s.close()
        return banner + "\n" + capa
    except:
        return ""


def ssh_probe(target, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(2048).decode(errors="ignore")
        if not banner.strip():
            s.send(b"SSH-2.0-Lightning\r\n")
            banner = s.recv(2048).decode(errors="ignore")
        s.close()
        return banner
    except:
        return ""


def telnet_probe(target, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(2048).decode(errors="ignore")
        s.close()
        return banner
    except:
        return ""


def redis_probe(target, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        s.send(b"INFO\r\n")
        data = s.recv(4096).decode(errors="ignore")
        s.close()
        return data
    except:
        return ""
def grab_banner(target, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(2048).decode(errors="ignore")
        s.close()
        return banner
    except:
        return ""
def smb_probe(target, port=445):
    try:
        from impacket.smbconnection import SMBConnection

        # '*' = negotiate best dialect automatically
        conn = SMBConnection(
            remoteName=target,
            remoteHost=target,
            sess_port=port,
            timeout=3
        )

        conn.login('', '')  # anonymous login attempt

        info = {
            "server_os": conn.getServerOS(),
            "server_name": conn.getServerName(),
            "domain": conn.getServerDomain(),
            "signing": conn.isSigningRequired(),
            "dialect": conn.getDialect()
        }

        conn.close()
        return info

    except Exception:
        return None
