# Lightning

Lightning is a Python-based SYN port scanner with OS, service, and vulnerability detection, plus pluggable scripts and exploit matching.

**Features**
- SYN port scanning with adjustable modes and batch sizes
- OS and service detection
- Script engine for service-specific checks
- Exploit matching and interactive REPL
- Passive recon (WHOIS + DNS)

**Quick Start**
```bash
python lightning.py <target>
```

**Common Usage**
```bash
# Scan a custom port range
python lightning.py <target> -p 1-4096

# Enable OS and service detection
python lightning.py <target> -O -S

# Run optional (active) scripts
python lightning.py <target> -S --active

# Run specific scripts only (comma-separated)
python lightning.py <target> -S --scripts http-sqli,http-robots

# Enable exploit matching prompts
python lightning.py <target> -S --exploit
```

**REPL**
Start the interactive shell:
```bash
python lightning.py
```
Useful commands inside the REPL:
```bash
scan <target> [ports]
services
scripts
exec <script.py>
exploits
use exploit/<name>
run
```

**Screencast**
`assets/screencast-2026-03-27-22-18-10.webm`

**Scripts**
Scripts live under `scripts/` and are loaded dynamically. Each script declares:
- `SERVICE` (e.g., `http`, `ssh`)
- `SCRIPT_NAME`
- `DESCRIPTION`
- `OPTIONAL`

Optional scripts run only with `--active` or when explicitly selected.

**Exploits**
Exploits live under `exploits/`. A sample module is included in `exploits/http_sample.py`.

**Dependencies**
Minimum:
- Python 3.9+

Recommended (enables full functionality):
```bash
pip install scapy requests beautifulsoup4 python-whois dnspython
```

Notes:
- SYN scans with Scapy typically require elevated privileges. If you get permission errors, run with `sudo`.
- WHOIS uses `python-whois`. If you see `module 'whois' has no attribute 'whois'`, uninstall `whois` and install `python-whois`.

**Project Structure**
```
lightning.py          # main CLI + REPL
script_engine.py      # script loader
exploit_engine.py     # exploit loader
scripts/              # service checks
exploits/             # exploit modules
osint/                # passive recon
```
