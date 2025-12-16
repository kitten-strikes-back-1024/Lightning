from scapy.all import IP, TCP, sr, send
import sys
from tqdm import tqdm
import osdetector
import servicedetector 
import vulnscanner 
import vulnsearcher
import argparse
from script_engine import ScriptEngine
import getpass
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

import random
import time
from rich.console import Console
from rich.panel import Panel
from rich.live import Live

console = Console()

LOGO = r"""
██╗     ██╗ ██████╗ ██╗  ██╗████████╗███╗   ██╗██╗███╗   ██╗ ██████╗
██║     ██║██╔════╝ ██║  ██║╚══██╔══╝████╗  ██║██║████╗  ██║██╔════╝
██║     ██║██║  ███╗███████║   ██║   ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
██║     ██║██║   ██║██╔══██║   ██║   ██║╚██╗██║██║██║╚██╗██║██║   ██║
███████╗██║╚██████╔╝██║  ██║   ██║   ██║ ╚████║██║██║ ╚████║╚██████╔╝
╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
"""

GLITCH_CHARS = "!@#$%^&*()_+=-[]{}<>?/\\|"

def glitch_text(text, intensity=0.08):
    result = ""
    for c in text:
        if c != "\n" and random.random() < intensity:
            result += random.choice(GLITCH_CHARS)
        else:
            result += c
    return result


def glitch_banner(duration=1.2, fps=18):
    frames = int(duration * fps)

    with Live(console=console, refresh_per_second=fps) as live:
        for _ in range(frames):
            glitched = glitch_text(LOGO)
            live.update(
                Panel.fit(
                    f"[bold bright_cyan]{glitched}[/]\n"
                    "[bold green]⚡ Lightning Network Scanner ⚡[/]\n"
                    "[dim]Fast • Modular • OSINT-powered[/]",
                    border_style="bright_cyan"
                )
            )
            time.sleep(1 / fps)
    console.clear()
    # Final clean logo
    console.print(
        Panel.fit(
            f"[bold bright_cyan]{LOGO}[/]\n"
            "[bold green]⚡ Lightning Network Scanner ⚡[/]\n"
            "[dim]Fast • Modular • OSINT-powered[/]",
            border_style="bright_cyan"
        )
    )


glitch_banner()


# NOTE: osdetector, vulnscanner, vulnsearcher servicedetector, script_engine, and service_db are non-installable by pip.
engine = ScriptEngine()




parser = argparse.ArgumentParser(
    description="Lightning - SYN Port Scanner with OS, Service & Vulnerability Detection"
)

parser.add_argument(
    "target",
    help="Target IP address or hostname"
)

parser.add_argument(
    "-p", "--ports",
    default="1-1024",
    help="Port range to scan (default: 1-1024)"
)

parser.add_argument(
    "-O",
    action="store_true",
    help="Enable OS detection"
)

parser.add_argument(
    "-S",
    action="store_true",
    help="Enable service detection"
)


args = parser.parse_args()
try:
    start_port, end_port = map(int, args.ports.split("-"))
    if not (1 <= start_port <= end_port <= 65535):
        raise ValueError
except ValueError:
    console.print("[bold red][!] Invalid port range. Use start-end (e.g. 1-1024)")
    sys.exit(1)

ports = range(start_port, end_port + 1)

target = args.target
os_enabled = args.O
service_enabled = args.S

### SERPAPI THING
def prompt_serpapi_key():
    console.print("[green][*] SerpAPI key required for OSINT vulnsearch. If you do not need this feature, please skip.")
    return getpass.getpass("Enter SerpAPI key (input hidden): ")


def prompt_nvd_key():
    console.print("[green][*] NVD key required for vulndetails search. If you do not need this feature, please skip.")
    return getpass.getpass("Enter NVD-API key (input hidden): ")


def syn_scan_parallel(target, ports):
    open_ports = []
    packets = []

    for port in tqdm(ports):
        packets.append(IP(dst=target)/TCP(dport=port, flags="S"))

    answered, _ = sr(
        packets,
        timeout=1,
        inter=0.002,
        retry=1,
        verbose=0
    )

    for sent, received in answered:
        if received.haslayer(TCP) and received[TCP].flags == 0x12:
            port = sent[TCP].dport
            open_ports.append(port)

            # polite RST
            send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)

    for port in open_ports:
        table = Table(title=f"Open Ports on {target}")
        table.add_column("Port", justify="center", style="bright_green")
        table.add_column("Status", justify="center", style="green")

        for port in open_ports:
            table.add_row(str(port), "OPEN")

    console.print(table)

    return open_ports


if __name__ == "__main__":

    console.print(f"[bright_cyan][+] Starting SYN scan on {target}")
    console.print(f"[bright_cyan][+] Scanning ports {start_port}-{end_port}")
    console.print(f"[green]-" * 40)

    open_ports = syn_scan_parallel(target, ports)

    if os_enabled:
        if open_ports:
            console.print(f"[bright_cyan]\n[+] Running OS detection...\n")
            osdetector.osdetect(target=target, openport=open_ports[0])
        else:
            console.print(f"[bright_cyan]\n[!] OS detection skipped (no open ports)")
    if service_enabled:
        if open_ports:
            console.print(f"[bright_cyan]\n[+] Running Service Detector...\n")

            services = []

            for port in open_ports:
                result = servicedetector.detect_service(target, port)
                if result:
                    result["port"] = port
                    services.append(result)

                    print(f"PORT {port}/tcp")
                    print(f" SERVICE : {result['service']}")
                    print(f" PRODUCT : {result['product']}")
                    if result['version']:
                        print(f" VERSION : {result['version']}")
                    print(f" CONFIDENCE : {result['confidence']}%\n")
            if services:
                y = input("Do you want to run scripts? (y/n): ")
                if y.lower() == "y":
                    for svc in services:
                        engine.run_scripts(
                            service=svc["service"],
                            target=target,
                            port=svc["port"],
                            args={}
                        )
            if services:
                x = input("Service scan complete. Do you want to check for vulnerabilities? (y/n): ")
                if x.lower() == "y":
                    z = input("OSINT search or database search? (osint/database)")
                    if z.lower() == "database":
                        nvdkey = prompt_nvd_key()
                        for svc in services:
                            if svc.get("version"):
                                vulns = vulnscanner.nvd_search(
                                    svc["service"],
                                    svc["version"],
                                    nvdapikey=nvdkey
                                )
                                for cve, desc in list(vulns.items())[:5]:
                                    print(f"\n{cve}")
                                    print(desc)
                    elif z.lower() == "osint":
                        for svc in services:
                            if svc.get("version"):
                                serpapikey = prompt_serpapi_key()
                                nvdkey = prompt_nvd_key()
                                cves, descs = vulnsearcher.vulnsearch(svc["service"], svc["version"], apikey=serpapikey, nvdapikey=nvdkey)
                                table = Table(title=f"Vulnerabilities for {svc['service']} {svc['version']}")
                                table.add_column("CVE", style="red")
                                table.add_column("Description", style="yellow")

                                for i in range(len(cves)):
                                    table.add_row(cves[i], descs[i])
                                
                            console.print(table)
                            

        else:
            print("\n[!] Service detector failed (no open ports)\n")
