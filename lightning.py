import psutil
import os
from scapy.all import IP, TCP, sr, send
import sys
from tqdm import tqdm
import osdetector
import servicedetector 
import vulnscanner 
import vulnsearcher
import argparse
from script_engine import ScriptEngine
from exploit_engine import ExploitEngine
import getpass
import json
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from osint.passive import run_passive_recon

console = Console()
process = psutil.Process(os.getpid())
import random
import time
from rich.live import Live

def get_memory_usage():
    """
    Returns the current memory usage of the Python process in MiB (megabytes).
    """
    process = psutil.Process(os.getpid())
    # memory_info().rss g
    # We convert it to megabytes for readability.
    mem_bytes = process.memory_info().rss
    mem_mib = mem_bytes / (1024 ** 2)
    return mem_mib


LOGO = r"""
██╗     ██╗ ██████╗ ██╗  ██╗████████╗███╗   ██╗██╗███╗   ██╗ ██████╗
██║     ██║██╔════╝ ██║  ██║╚══██╔══╝████╗  ██║██║████╗  ██║██╔════╝
██║     ██║██║  ███╗███████║   ██║   ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
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
                    "[dim]MADE BY THE KITTEN ⚡ [/]",
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
exploit_engine = ExploitEngine()
exploit_engine.load_exploits()




parser = argparse.ArgumentParser(
    description="Lightning - SYN Port Scanner with OS, Service & Vulnerability Detection"
)

parser.add_argument(
    "target",
    nargs="?",
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

parser.add_argument(
    "--active",
    action="store_true",
    help="Enable active / optional scripts"
)

parser.add_argument(
    "--exploit",
    action="store_true",
    help="Enable exploit matching and prompts"
)

parser.add_argument(
    "--scripts",
    help="Comma-separated list of scripts to run (overrides defaults)"
)

parser.add_argument(
    "--batch-size",
    type=int,
    default=256,
    help="Batch size for packet sends to reduce RAM (default: 256)"
)

parser.add_argument(
    "--summary",
    action="store_true",
    help="Generate an AI scan summary using Gemini"
)

parser.add_argument(
    "--mode",
    choices=["normal", "stealth", "aggressive", "evade"],
    default="normal",
    help="Scan mode: stealth (slower), aggressive (faster), evade (randomized order/TTL)"
)

parser.add_argument(
    "--save",
    help="Save scan results to a JSON file"
)

parser.add_argument(
    "--load",
    help="Load scan results from a JSON file (skips scanning)"
)


args = parser.parse_args()


def parse_port_range(ports_spec):
    try:
        start_port, end_port = map(int, ports_spec.split("-"))
        if not (1 <= start_port <= end_port <= 65535):
            raise ValueError
        return start_port, end_port, range(start_port, end_port + 1), None
    except ValueError:
        return None, None, None, "[!] Invalid port range. Use start-end (e.g. 1-1024)"

def prompt_gemini_key():
    console.print("[green][*] Gemini API key required for AI scan summary. If you do not need this feature, please skip.")
    return getpass.getpass("Enter Gemini API key (input hidden): ")

def syn_scan_parallel(target, ports, batch_size=256, mode="normal"):
    """Perform SYN scan in batches to reduce memory usage.

    Args:
        target: target IP/hostname
        ports: iterable of port numbers
        batch_size: number of packets to send per batch
        mode: normal | stealth | aggressive | evade

    Returns:
        list of open ports
    """
    open_ports = []

    # materialize ports to allow slicing without building packet objects
    ports_list = list(ports)
    if mode in ("evade", "stealth"):
        random.shuffle(ports_list)

    # mode tuning
    if mode == "stealth":
        timeout = 2
        inter = 0.01
        retry = 1
        jitter_range = (0.05, 0.2)
    elif mode == "aggressive":
        timeout = 0.5
        inter = 0.0005
        retry = 0
        jitter_range = None
    elif mode == "evade":
        timeout = 1
        inter = 0.003
        retry = 1
        jitter_range = (0.02, 0.08)
    else:
        timeout = 1
        inter = 0.002
        retry = 1
        jitter_range = None

    total = len(ports_list)
    print(f"Initial memory usage: {get_memory_usage():.2f} MiB")
    with tqdm(total=total) as pbar:
        for i in range(0, total, batch_size):
            batch = ports_list[i:i + batch_size]
            if mode == "evade":
                packets = [
                    IP(dst=target, ttl=random.choice([32, 64, 96, 128])) / TCP(dport=port, flags="S")
                    for port in batch
                ]
            else:
                packets = [IP(dst=target) / TCP(dport=port, flags="S") for port in batch]

            answered, _ = sr(
                packets,
                timeout=timeout,
                inter=inter,
                retry=retry,
                verbose=0
            )

            for sent, received in answered:
                if received.haslayer(TCP) and received[TCP].flags == 0x12:
                    port = sent[TCP].dport
                    open_ports.append(port)

                    # polite RST
                    send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
            
            pbar.update(len(batch))

            if jitter_range:
                time.sleep(random.uniform(*jitter_range))

    # Print results table once
    if open_ports:
        table = Table(title=f"Open Ports on {target}")
        table.add_column("Port", justify="center", style="bright_green")
        table.add_column("Status", justify="center", style="green")

        for port in sorted(open_ports):
            table.add_row(str(port), "OPEN")

        console.print(table)

    return open_ports


def build_summary_payload(target, port_range, open_ports, os_result, services, vulns, exploits):
    lines = []
    lines.append(f"Target: {target}")
    lines.append(f"Port range: {port_range[0]}-{port_range[1]}")
    lines.append(f"Open ports: {', '.join(map(str, open_ports)) if open_ports else 'none'}")

    if os_result:
        lines.append(f"OS guess: {os_result.get('os')} ({os_result.get('confidence')}% confidence)")

    if services:
        lines.append("Services:")
        for svc in services:
            version = f" {svc['version']}" if svc.get("version") else ""
            lines.append(f"- {svc['service']} {svc['product']}{version} (port {svc['port']}, {svc['confidence']}%)")

    if vulns:
        lines.append("Vulnerabilities:")
        for v in vulns:
            header = f"- {v['service']} {v.get('product', '')} {v.get('version', '')}".strip()
            lines.append(header)
            for cve in v.get("cves", [])[:5]:
                lines.append(f"  {cve}")

    if exploits:
        lines.append("Exploit matches:")
        for e in exploits:
            lines.append(f"- {e['service']}:{e['port']} -> {', '.join(e['names'])}")

    return "\n".join(lines)


def gemini_generate_summary(summary_text, api_key, model="gemini-2.5-flash"):
    try:
        from google import genai
    except Exception as e:
        return None, f"Missing google-genai SDK: {e}"

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model,
            contents=(
                "You are a security scan assistant. Summarize the scan results "
                "in concise bullet points and include 2-3 actionable next steps. "
                "Do not invent findings.\n\n"
                f"{summary_text}"
            ),
        )
        return response.text, None
    except Exception as e:
        return None, str(e)


def save_results(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Saved scan results to {path}")
        return True
    except Exception as e:
        print(f"[!] Failed to save results: {e}")
        return False


def load_results(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), None
    except Exception as e:
        return None, str(e)


def run_service_detection(target, open_ports):
    services = []
    if not open_ports:
        console.print(f"[bright_cyan]\n[!] Service detection skipped (no open ports)")
        return services

    console.print(f"[bright_cyan]\n[+] Running Service Detector...\n")
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

    return services


def run_os_detection(target, open_ports):
    if not open_ports:
        console.print(f"[bright_cyan]\n[!] OS detection skipped (no open ports)")
        return None
    console.print(f"[bright_cyan]\n[+] Running OS detection...\n")
    return osdetector.osdetect(target=target, openport=open_ports[0])


def run_script_engine(target, services, active=False, selected_scripts=None):
    if not services:
        print("[!] No services available. Run services first.")
        return
    for svc in services:
        engine.run_scripts(
            service=svc["service"],
            target=target,
            port=svc["port"],
            args={"active": active,
                  "scripts": selected_scripts
                  }
        )


def run_vuln_search(services):
    vuln_results = []
    for svc in services:
        if svc.get("version"):
            cves, descs = vulnsearcher.vulnsearch(svc["product"], svc["version"])
            table = Table(title=f"Vulnerabilities for {svc['product']} {svc['version']}")
            table.add_column("CVE", style="red")
            table.add_column("Description", style="yellow")

            for cve in cves:
                table.add_row(cve, descs.get(cve) or "N/A")
            
            console.print(table)
            if cves:
                vuln_results.append({
                    "service": svc["service"],
                    "product": svc["product"],
                    "version": svc["version"],
                    "cves": cves,
                })
    return vuln_results


def run_exploit_matching(target, services, os_result=None):
    exploit_matches = []
    if not exploit_engine.exploits:
        print("[!] No exploits loaded")
        return exploit_matches

    total_matches = 0
    os_name = os_result.get("os") if os_result else None
    for svc in services:
        matches = exploit_engine.match(svc["service"], svc["port"], os_name=os_name)
        if not matches:
            continue

        total_matches += len(matches)

        table = Table(title=f"Exploits for {svc['service']} on {target}:{svc['port']}")
        table.add_column("Name", style="red")
        table.add_column("Port", justify="center", style="cyan")
        table.add_column("Description", style="yellow")

        for exp in matches:
            name = getattr(exp, "NAME", exp.__name__)
            desc = getattr(exp, "DESCRIPTION", "No description")
            table.add_row(name, str(svc["port"]), desc)

        console.print(table)
        exploit_matches.append({
            "service": svc["service"],
            "port": svc["port"],
            "names": [getattr(exp, "NAME", exp.__name__) for exp in matches],
        })

    if total_matches == 0:
        print("[!] No matching exploits found")

    return exploit_matches


def run_precon(target):
    if not target:
        print("[!] Usage: precon <target>")
        return

    console.print(f"[bright_cyan]\n[+] Running passive recon on {target}...\n")
    results = run_passive_recon(target)

    whois_data = results.get("whois")
    if whois_data:
        table = Table(title=f"WHOIS for {target}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        for key, value in whois_data.items():
            if value:
                table.add_row(key, str(value))
        console.print(table)
    else:
        console.print("[yellow][!] WHOIS data unavailable")

    dns_data = results.get("dns")
    if dns_data:
        table = Table(title=f"DNS Records for {target}")
        table.add_column("Type", style="cyan")
        table.add_column("Records", style="green")
        for rtype in ("A", "AAAA", "MX", "NS"):
            records = dns_data.get(rtype) or []
            if records:
                table.add_row(rtype, ", ".join(records))
            else:
                table.add_row(rtype, "None")
        console.print(table)

        if dns_data.get("errors"):
            for err in dns_data["errors"]:
                console.print(f"[yellow][!] DNS: {err}")
    else:
        console.print("[yellow][!] DNS data unavailable")

    if results.get("errors"):
        for err in results["errors"]:
            console.print(f"[yellow][!] {err}")


def build_exploit_map():
    mapping = {}
    for exp in exploit_engine.exploits:
        name = getattr(exp, "NAME", None) or exp.__name__.split(".")[-1]
        path = exp.__name__.replace(".", "/")
        mapping[name.lower()] = exp
        mapping[path.lower()] = exp
    return mapping


def build_script_map():
    mapping = {}
    for service, modules in engine.scripts.items():
        for mod in modules:
            script_name = getattr(mod, "SCRIPT_NAME", None) or mod.__name__.split(".")[-1]
            module_name = mod.__name__.split(".")[-1]
            mapping[script_name.lower()] = mod
            mapping[module_name.lower()] = mod
    return mapping


def run_named_script(target, services, script_module, active=False, selected_scripts=None):
    if not target:
        print("[!] Run scan first.")
        return
    if not services:
        print("[!] Run services first.")
        return

    service_name = getattr(script_module, "SERVICE", None)
    if not service_name:
        print("[!] Script missing SERVICE attribute.")
        return

    matched = [s for s in services if s.get("service") == service_name]
    if not matched:
        print(f"[!] No matching service '{service_name}' found in current results.")
        return

    for svc in matched:
        try:
            script_module.run(target, svc["port"], {"active": active, "scripts": selected_scripts})
        except Exception as e:
            print(f"[!] Script {getattr(script_module, 'SCRIPT_NAME', script_module.__name__)} failed: {e}")


def repl():
    state = {
        "target": None,
        "ports_spec": "1-1024",
        "start_port": 1,
        "end_port": 1024,
        "ports": range(1, 1025),
        "mode": "normal",
        "batch_size": 256,
        "active": False,
        "selected_scripts": None,
        "open_ports": [],
        "services": [],
        "os_result": None,
        "vuln_results": [],
        "exploit_matches": [],
        "selected_exploit": None,
    }

    exploit_map = build_exploit_map()
    script_map = build_script_map()

    def prompt():
        if state["selected_exploit"]:
            name = getattr(state["selected_exploit"], "NAME", None) or state["selected_exploit"].__name__
            return f"lightning ({name}) > "
        return "lightning > "

    while True:
        try:
            raw = input(prompt()).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if not raw:
            continue

        parts = raw.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("exit", "quit"):
            break
        if cmd in ("help", "?"):
            print("Commands: scan <target> [ports], ports <start-end>, mode <normal|stealth|aggressive|evade>")
            print("          precon <target>, services, os, scripts, exec <script.py>, vulns, osint, exploits, use exploit/<name>, run, back, exit")
            continue

        if cmd == "scan":
            if not args:
                print("[!] Usage: scan <target> [ports]")
                continue
            state["target"] = args[0]
            if len(args) > 1:
                state["ports_spec"] = args[1]
            start_port, end_port, ports, err = parse_port_range(state["ports_spec"])
            if err:
                print(err)
                continue
            state["start_port"] = start_port
            state["end_port"] = end_port
            state["ports"] = ports
            console.print(f"[bright_cyan][+] Starting SYN scan on {state['target']}")
            console.print(f"[bright_cyan][+] Scanning ports {start_port}-{end_port}")
            console.print(f"[green]-" * 40)
            state["open_ports"] = syn_scan_parallel(
                state["target"],
                state["ports"],
                batch_size=state["batch_size"],
                mode=state["mode"]
            )
            continue

        if cmd == "ports":
            if not args:
                print("[!] Usage: ports <start-end>")
                continue
            state["ports_spec"] = args[0]
            start_port, end_port, ports, err = parse_port_range(state["ports_spec"])
            if err:
                print(err)
                continue
            state["start_port"] = start_port
            state["end_port"] = end_port
            state["ports"] = ports
            print(f"[+] Port range set to {start_port}-{end_port}")
            continue

        if cmd == "mode":
            if not args or args[0] not in ("normal", "stealth", "aggressive", "evade"):
                print("[!] Usage: mode <normal|stealth|aggressive|evade>")
                continue
            state["mode"] = args[0]
            print(f"[+] Scan mode set to {state['mode']}")
            continue

        if cmd == "services":
            if not state["target"]:
                print("[!] Run scan first.")
                continue
            state["services"] = run_service_detection(state["target"], state["open_ports"])
            continue

        if cmd == "precon":
            if args:
                state["target"] = args[0]
            run_precon(state["target"])
            continue

        if cmd == "os":
            if not state["target"]:
                print("[!] Run scan first.")
                continue
            state["os_result"] = run_os_detection(state["target"], state["open_ports"])
            continue

        if cmd == "scripts":
            if not state["target"]:
                print("[!] Run scan first.")
                continue
            run_script_engine(
                state["target"],
                state["services"],
                active=state["active"],
                selected_scripts=state["selected_scripts"]
            )
            continue

        if cmd == "exec":
            if not args:
                print("[!] Usage: exec <script.py>")
                continue
            name = args[0].lower()
            if name.endswith(".py"):
                name = name[:-3]
            script = script_map.get(name)
            if not script:
                print("[!] Script not found")
                continue
            run_named_script(
                state["target"],
                state["services"],
                script,
                active=state["active"],
                selected_scripts=state["selected_scripts"]
            )
            continue

        if cmd in ("vulns", "osint"):
            if not state["services"]:
                print("[!] Run services first.")
                continue
            state["vuln_results"] = run_vuln_search(state["services"])
            continue

        if cmd == "exploits":
            if not state["services"]:
                print("[!] Run services first.")
                continue
            state["exploit_matches"] = run_exploit_matching(
                state["target"],
                state["services"],
                os_result=state["os_result"]
            )
            continue

        if cmd == "use":
            if not args:
                print("[!] Usage: use exploit/<name>")
                continue
            key = args[0].lower()
            key = key.replace("exploit/", "")
            selected = exploit_map.get(key) or exploit_map.get(f"exploits/{key}")
            if not selected:
                print("[!] Exploit not found")
                continue
            state["selected_exploit"] = selected
            continue

        if cmd == "back":
            state["selected_exploit"] = None
            continue

        if cmd == "run":
            exp = state["selected_exploit"]
            if not exp:
                print("[!] No exploit selected. Use: use exploit/<name>")
                continue
            if not state["services"]:
                print("[!] Run services first.")
                continue
            info = getattr(exp, "INFO", {})
            exp_service = info.get("service")
            exp_port = info.get("port")
            svc = None
            for s in state["services"]:
                if exp_service and exp_port:
                    if s["service"] == exp_service and s["port"] == exp_port:
                        svc = s
                        break
            if not svc:
                svc = state["services"][0]
            if hasattr(exp, "run"):
                try:
                    exp.run(state["target"], svc["port"], svc)
                except Exception as e:
                    print(f"[!] Exploit failed: {e}")
            else:
                print("[!] Exploit has no run() function")
            continue

        print("[!] Unknown command. Type 'help' for commands.")


if __name__ == "__main__":

    if args.target is None:
        repl()
        sys.exit(0)

    selected_scripts = None
    if args.scripts:
        selected_scripts = set(s.strip() for s in args.scripts.split(","))

    start_port, end_port, ports, err = parse_port_range(args.ports)
    if err:
        console.print(f"[bold red]{err}")
        sys.exit(1)

    target = args.target
    os_enabled = args.O
    service_enabled = args.S

    console.print(f"[bright_cyan][+] Starting SYN scan on {target}")
    console.print(f"[bright_cyan][+] Scanning ports {start_port}-{end_port}")
    console.print(f"[green]-" * 40)

    open_ports = []
    services = []
    os_result = None
    vuln_results = []
    exploit_matches = []

    loaded = False
    if args.load:
        data, err = load_results(args.load)
        if err:
            print(f"[!] Failed to load results: {err}")
        else:
            open_ports = data.get("open_ports", [])
            services = data.get("services", [])
            os_result = data.get("os_result")
            vuln_results = data.get("vuln_results", [])
            exploit_matches = data.get("exploit_matches", [])
            loaded = True
            print(f"[+] Loaded scan results from {args.load}")

    if not loaded:
        open_ports = syn_scan_parallel(target, ports, batch_size=args.batch_size)

    if os_enabled and not loaded:
        os_result = run_os_detection(target, open_ports)
    if service_enabled and not loaded:
        services = run_service_detection(target, open_ports)
        if services:
            y = input("Do you want to run scripts? (y/n): ")
            if y.lower() == "y":
                run_script_engine(
                    target,
                    services,
                    active=args.active,
                    selected_scripts=selected_scripts
                )
        if services:
            x = input("Service scan complete. Do you want to check for vulnerabilities? (y/n): ")
            if x.lower() == "y":
                vuln_results = run_vuln_search(services)
                            
            if services:
                run_exploits = args.exploit
                if not run_exploits:
                    run_exploits = input("Service scan complete. Do you want to check for exploits? (y/n): ").lower() == "y"

                if run_exploits:
                    exploit_matches = run_exploit_matching(
                        target,
                        services,
                        os_result=os_result
                    )
                    for svc in services:
                        matches = exploit_engine.match(svc["service"], svc["port"])
                        for exp in matches:
                            name = getattr(exp, "NAME", exp.__name__)
                            confirm = input(f"Run exploit {name} on {target}:{svc['port']}? (y/n): ")
                            if confirm.lower() == "y":
                                if hasattr(exp, "run"):
                                    try:
                                        exp.run(target, svc["port"], svc)
                                    except Exception as e:
                                        print(f"[!] Exploit {name} failed: {e}")
                                else:
                                    print(f"[!] Exploit {name} has no run() function")

        else:
            print("\n[!] Service detector failed (no open ports)\n")

    if args.save:
        payload = {
            "target": target,
            "port_range": [start_port, end_port],
            "open_ports": open_ports,
            "os_result": os_result,
            "services": services,
            "vuln_results": vuln_results,
            "exploit_matches": exploit_matches,
        }
        save_results(args.save, payload)

    if args.summary:
        gemini_key = prompt_gemini_key()
        if gemini_key:
            summary_text = build_summary_payload(
                target=target,
                port_range=(start_port, end_port),
                open_ports=open_ports,
                os_result=os_result,
                services=services,
                vulns=vuln_results,
                exploits=exploit_matches,
            )
            summary, err = gemini_generate_summary(summary_text, gemini_key)
            if err:
                print(f"[!] Gemini summary failed: {err}")
            else:
                console.print(Panel.fit(summary, title="AI Scan Summary", border_style="bright_magenta"))
