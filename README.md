⚡ Lightning
===========

**Lightning** is a fast, modular, open-source, **SYN-based network scanner** with OS detection, service fingerprinting, scriptable enumeration, and OSINT-powered vulnerability discovery — built in Python for learning, CTFs, and **real-world reconnaissance**.


🤝 Contributing
---------------


This project is built for learning and is left open source. It would _really_ help me if you could contribute in any way you want. 

If you want to contribute:


*   **Add scripts in scripts/**
    
*   Improve fingerprints
    
*   Harden error handling

*   Add more entries to the databases(moving them from Python to SQL soon...)

*   Add more kinds of probes to probes.py

I thank everybody who has made even the slightest contribution to this project.

🛣 Improvements
----------

This project is still under development, and there are _so many_ things I am yet to add. If you are interested in helping, please reach out.

*   SSH enum (auth methods, banner parsing)
    
*   TLS certificate analysis
    
*   Subdomain enumeration
    
*   Port forwarding / tunnel detection
    
*   Default credential checks (opt-in)
    
*   CVE exploit correlation
    
*   Output export (JSON)
    
*   Async scanning engine

✨ Features
----------

*   ⚡ **High-speed SYN port scanning** (Scapy)
    
*   🧠 **OS detection** via TCP fingerprinting
    
*   🔍 **Service & version detection** (Banner grabbing and other probes)
    
*   🧩 **Script engine** (NSE-style, auto-loaded modules)
    
*   🕵️ **OSINT vulnerability search** (Google + NVD)
    
*   📚 **NVD database vulnerability lookup**
    
*   🌐 **HTTP enumeration**
    
    *   Security headers
        
    *   Methods
        
    *   robots.txt
        
    *   CMS detection (WordPress, Joomla, Drupal, GitLab, Gitea)
        
*   🔐 **FTP enumeration**
    
    *   Anonymous login
        
    *   User enumeration
        
*   🎨 **Rich-powered UI**
    
    *   Glitch intro banner
        
    *   Colored output
        
*   🔑 **User-supplied API keys** (never stored)
    

📂 Project Structure
--------------------

```text
Lightning/
├── lightning.py           # Main scanner
├── script_engine.py       # Dynamic script loader
├── scripts/               # Service scripts (ftp, http, ssh, etc.)
│   ├── ftp_*.py
│   ├── http_*.py
│   └── ssh_*.py
├── servicedetector.py     # Service fingerprinting
├── osdetector.py          # OS detection logic
├── vulnscanner.py         # NVD database search
├── vulnsearcher.py        # OSINT vulnerability search
├── service_db.py          # Probe & signature DB
├── probes.py              # TCP probes
└── README.md
```
🚀 Usage
--------

```bash
sudo python3 lightning.py -O -S` 
```
### Examples

Scan top ports with OS & service detection:

```bash
sudo python3 lightning.py -O -S 10.10.10.10  `
```
Custom port range:

```Bash
sudo python3 lightning.py -S -p 1-65535 10.10.10.10   `
```
🧩 Script Engine
----------------

Lightning automatically loads scripts from the scripts/ directory.

Each script must define:

```python
SERVICE = "http"   # or ftp, ssh, etc.

DESCRIPTION = "What this script does"

def run(target, port, args):

....

```
Scripts are executed **only when the matching service is detected**.

### Example Scripts

*   ftp\_anon.py → anonymous login check
    
*   http\_headers.py → missing security headers
    
*   http\_cms.py → CMS detection + versioning
    
*   ssh\_enum.py → auth method discovery (planned)
    

🔍 Vulnerability Scanning
-------------------------

After service detection, Lightning supports **two vulnerability modes**:

### 1️⃣ Database Mode (NVD)

Uses the official NVD API.

You will be prompted for:

*   NVD API key
    

### 2️⃣ OSINT Mode

Uses Google search (SerpAPI) + NVD enrichment.

You will be prompted for:

*   SerpAPI key
    
*   NVD API key
    

⚠️ **Keys are never stored or logged.**

🎨 UI
-----

Lightning uses:

*   rich → panels, colors, live rendering
    
*   tqdm → progress bars (being migrated to Rich)
    

Includes:

*   Animated glitch intro
    
*   Clean, readable output
    
*   Minimal noise
    

⚠️ Disclaimer
-------------

> Lightning is intended **for educational use, labs, CTFs, and systems you own or are authorized to test**.

Do **NOT** scan networks you do not have permission to test.

You are responsible for how you use this tool.


