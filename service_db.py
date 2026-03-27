SERVICE_DB = {

    # ---------------- SSH ----------------
    22: {
        "service": "ssh",
        "fingerprints": {
            "OpenSSH": {
                "patterns": [r"OpenSSH[_/-]([\w\.p]+)"],
                "score": 80
            },
            "Dropbear": {
                "patterns": [r"dropbear[_/-]([\w\.]+)"],
                "score": 75
            },
            "Cisco SSH": {
                "patterns": [r"Cisco[- ]SSH"],
                "score": 60
            }
        }
    },

    # ---------------- FTP ----------------
    21: {
        "service": "ftp",
        "fingerprints": {
            "vsFTPd": {
                "patterns": [r"vsftpd\s*([\d\.]+)"],
                "score": 85
            },
            "ProFTPD": {
                "patterns": [r"ProFTPD\s*([\d\.]+)"],
                "score": 80
            },
            "Pure-FTPd": {
                "patterns": [r"Pure-FTPd"],
                "score": 70
            },
            "FileZilla": {
                "patterns": [r"FileZilla Server\s*([\d\.]+)"],
                "score": 80
            }
        }
    },

    # ---------------- Telnet ----------------
    23: {
        "service": "telnet",
        "fingerprints": {
            "BusyBox Telnet": {
                "patterns": [r"BusyBox"],
                "score": 75
            },
            "Cisco Telnet": {
                "patterns": [r"Cisco"],
                "score": 70
            }
        }
    },

    # ---------------- SMTP ----------------
    25: {
        "service": "smtp",
        "fingerprints": {
            "Postfix": {
                "patterns": [r"Postfix"],
                "score": 80
            },
            "Exim": {
                "patterns": [r"Exim\s*([\d\.]+)"],
                "score": 80
            },
            "Sendmail": {
                "patterns": [r"Sendmail"],
                "score": 70
            }
        }
    },

    # ---------------- DNS ----------------
    53: {
        "service": "dns",
        "fingerprints": {
            "BIND": {
                "patterns": [r"BIND\s*([\d\.]+)"],
                "score": 80
            },
            "dnsmasq": {
                "patterns": [r"dnsmasq"],
                "score": 75
            }
        }
    },

    # ---------------- HTTP ----------------
    80: {
        "service": "http",
        "fingerprints": {
            "Apache": {
                "patterns": [r"Apache/([\d\.]+)"],
                "score": 70
            },
            "Nginx": {
                "patterns": [r"nginx/([\d\.]+)"],
                "score": 70
            },
            "Microsoft IIS": {
                "patterns": [r"Microsoft-IIS/([\d\.]+)"],
                "score": 85
            },
            "LiteSpeed": {
                "patterns": [r"LiteSpeed"],
                "score": 65
            },
            "Caddy": {
                "patterns": [r"Caddy"],
                "score": 60
            }
        }
    },

    # ---------------- HTTPS ----------------
    443: {
        "service": "https",
        "fingerprints": {
            "Apache": {
                "patterns": [r"Apache/([\d\.]+)"],
                "score": 70
            },
            "Nginx": {
                "patterns": [r"nginx/([\d\.]+)"],
                "score": 70
            },
            "Cloudflare": {
                "patterns": [r"cloudflare"],
                "score": 90
            }
        }
    },

    # ---------------- POP3 ----------------
    110: {
        "service": "pop3",
        "fingerprints": {
            "Dovecot": {
                "patterns": [r"Dovecot"],
                "score": 80
            },
            "Courier": {
                "patterns": [r"Courier"],
                "score": 75
            }
        }
    },

    # ---------------- IMAP ----------------
    143: {
        "service": "imap",
        "fingerprints": {
            "Dovecot": {
                "patterns": [r"Dovecot"],
                "score": 80
            },
            "Courier": {
                "patterns": [r"Courier"],
                "score": 75
            }
        }
    },

    # ---------------- SMB ----------------
    445: {
        "service": "smb",
        "fingerprints": {
            "Samba": {
                "patterns": [r"Samba\s*([\d\.]+)"],
                "score": 85
            },
            "Windows SMB": {
                "patterns": [r"Windows"],
                "score": 70
            }
        }
    },

    # ---------------- RDP ----------------
    3389: {
        "service": "rdp",
        "fingerprints": {
            "Microsoft RDP": {
                "patterns": [r"Cookie: mstshash"],
                "score": 90
            }
        }
    },

    # ---------------- Redis ----------------
    6379: {
        "service": "redis",
        "fingerprints": {
            "Redis": {
                "patterns": [r"redis_version:([\d\.]+)"],
                "score": 95
            }
        }
    },

    # ---------------- Docker API ----------------
    2375: {
        "service": "docker",
        "fingerprints": {
            "Docker API": {
                "patterns": [r"Docker"],
                "score": 95
            }
        }
    },

    # ---------------- Kubernetes API ----------------
    6443: {
        "service": "kubernetes",
        "fingerprints": {
            "Kubernetes API": {
                "patterns": [r"kubernetes"],
                "score": 95
            }
        }
    },

    # ---------------- MongoDB ----------------
    27017: {
        "service": "mongodb",
        "fingerprints": {
            "MongoDB": {
                "patterns": [r"MongoDB"],
                "score": 90
            }
        }
    }
}

