
# Advanced CVEScannerX for Kali Linux

We introduce **CVEScannerX**, an enhanced Python-based scanner for known CVEs on Kali Linux. It extends the concept of CVEScannerV2 by combining local package checks and remote Nmap-based service detection with multiple vulnerability intelligence APIs (NVD, Vulners, Shodan, SecurityTrails, Exploit-DB). CVEScannerX supports scanning IPs, domain names, or the local machine, and correlates discovered CVEs with known exploits. It provides an interactive CLI (using Rich) and exports results in structured formats (JSON, HTML, and optional PDF).

CVEScannerX relies on **Nmap’s version detection** (as CVEScannerV2 did) to identify services on remote hosts. For local scans, it uses **Debian’s debsecan** tool to list vulnerabilities of installed packages. Detected services or packages are then queried against the NIST NVD API and the Vulners database to retrieve CVE details. It also fetches additional context via the **Shodan API** and **SecurityTrails API**, and uses `searchsploit` to correlate CVEs with public exploits. The results are presented in a clean table and written to JSON/HTML reports (PDF via wkhtmltopdf).

**Key Features:**

* **Local and Remote Scanning:** Supports *local* (Debian package) and *remote* (IP/domain) scans.
* **Multi-Source CVE Intelligence:** Queries NVD API, Vulners, Exploit-DB (via searchsploit), Shodan, and SecurityTrails.
* **CVE-Exploit Correlation:** Uses `searchsploit --cve` with JSON output to link CVEs to exploits.
* **Interactive CLI/TUI:** Offers prompts and colored tables (Rich library) for ease of use.
* **Structured Output:** Saves results in JSON, HTML (and PDF via wkhtmltopdf) for reporting.
* **Modular & Configurable:** Written in Python 3, organized into functions; API keys configurable via environment.

## Implementation Details

CVEScannerX is implemented as a single Python script (`cvescannerx.py`) with modular functions:

* **Local Scan (`scan_local`)**: Invokes `debsecan --format=json` to enumerate installed Debian packages and their CVEs. Debsecan “analyzes the list of installed packages on the current host and reports vulnerabilities found on the system”.
* **Remote Scan (`scan_remote`)**: Uses the `python-nmap` library to run `nmap -sV` (version scan) on the target IP or domain, collecting open ports and service/version info. Nmap’s service/version detection identifies software which can then be checked against CVE data.
* **Vulnerability Lookup**:

  * **NVD API**: Sends REST queries to NVD (e.g. `/cves/2.0?cveId=CVE-YYYY-NNNN`) or by CPE name. NVD returns official CVE details in JSON.
  * **Vulners API**: Uses the Vulners Python SDK to search for matching CVE records (e.g. by product name or “software: XXX 1.2.3” queries). Vulners aggregates many sources and often includes exploit info.
  * **Shodan API**: For a given IP, fetches host info (open ports, banners, known CVEs). Example code uses `shodan.Shodan(API_KEY).host()`.
  * **SecurityTrails API**: For a domain/IP, retrieves DNS history, subdomains, WHOIS, etc. (using the `securitytrails` Python wrapper).
* **Exploit Correlation (`search_exploits_by_cve`)**: Calls the local `searchsploit` tool with `--cve CVE-ID --json` to find any Exploit-DB entries tagged with that CVE. The JSON output is parsed and linked to each CVE. (On Kali, `exploitdb` is typically pre-installed; if not, it can be installed via `sudo apt install exploitdb`).
* **CLI/TUI and Reporting**: Uses the Rich library to display a formatted table of CVE, description, severity, and associated exploit titles. Results are also written to JSON and HTML files. For PDF reports, we generate HTML and convert via `wkhtmltopdf` (an open-source HTML-to-PDF tool).

Each major function is well-commented in the code (below) for clarity. Sensitive API keys (Shodan, Vulners, SecurityTrails, NVD) are read from environment variables (`SHODAN_API_KEY`, etc.). This modular design (clear functions for scanning, queries, output) makes the codebase maintainable and extensible.

## Installation & Dependencies

Install required system packages and Python libraries on your Kali Linux machine. For example:

```bash
# Update and install system packages
sudo apt update
sudo apt install -y nmap exploitdb debsecan wkhtmltopdf

# Install Python 3 libraries (use pip3 for Python 3)
pip3 install python-nmap shodan vulners securitytrails rich
pip3 install requests jinja2  # General utilities
```

* **nmap** (for network scanning)
* **exploitdb** (provides `searchsploit` for exploits)
* **debsecan** (for local package CVE scan)
* **wkhtmltopdf** (for optional PDF reports)
* **python-nmap** (Nmap XML parser library)
* **shodan** (Python wrapper for Shodan API)
* **vulners** (Vulners API client)
* **securitytrails** (SecurityTrails API wrapper)
* **rich** (for console output formatting)
* **requests, jinja2** (for API requests and templating)

Ensure you have API keys for Shodan, Vulners, and SecurityTrails (set in `~/.bashrc` or export before running), e.g.:

```bash
export SHODAN_API_KEY="YOUR_SHODAN_KEY"
export VULNERS_API_KEY="YOUR_VULNERS_KEY"
export SECURITYTRAILS_API_KEY="YOUR_SECURITYTRAILS_KEY"
export NVD_API_KEY="YOUR_NVD_KEY"  # optional
```

## Usage

Make the script executable and run it:

```bash
chmod +x cvescannerx.py
sudo ./cvescannerx.py --target 192.168.1.100 --format html --output scan_report
```

* **Interactive Mode:** If no `--target` is given, the script prompts you to choose local or remote scan and enter a hostname/IP.
* **Remote Scan:** Use `--target IP_or_domain`. Optionally specify `--ports 80,443` to scan specific ports (default is all).
* **Local Scan:** Use `--target local` to scan the host’s installed packages.
* **Output:** Use `--format` (`json`, `html`, or `pdf`) and `--output` to specify an output file base name. For PDF, ensure `wkhtmltopdf` is installed.

The script will display a table of discovered CVEs and save detailed reports. Below is the complete code.

## Code: `cvescannerx.py`

```python
#!/usr/bin/env python3
# File: cvescannerx.py

"""
CVEScannerX: Advanced CVE scanning tool for Kali Linux.

Features:
- Local and remote vulnerability scanning (unauthenticated).
- Queries multiple threat intelligence sources: NVD, Vulners, Exploit-DB, Shodan, SecurityTrails.
- Correlates CVEs with known exploits.
- Interactive CLI using Rich for colorful output.
- Outputs in JSON, HTML, PDF (optional).
"""

import os
import sys
import argparse
import subprocess
import json
import socket
import requests
from datetime import datetime
from collections import defaultdict
from rich.console import Console
from rich.table import Table

# Optional libraries (import if installed)
try:
    import nmap
except ImportError:
    nmap = None
try:
    import vulners
except ImportError:
    vulners = None
try:
    import shodan
except ImportError:
    shodan = None
try:
    from securitytrails import SecurityTrails
except ImportError:
    SecurityTrails = None

# API keys from environment (configure these)
SHODAN_API_KEY      = os.getenv('SHODAN_API_KEY')
VULNERS_API_KEY     = os.getenv('VULNERS_API_KEY')
SECURITYTRAILS_API_KEY = os.getenv('SECURITYTRAILS_API_KEY')
NVD_API_KEY         = os.getenv('NVD_API_KEY')  # optional

console = Console()

def scan_local():
    """
    Scan local system for installed package vulnerabilities using debsecan.
    """
    console.print("[bold green]Scanning local system for vulnerabilities...[/bold green]")
    try:
        # Use debsecan JSON output
        result = subprocess.check_output(['debsecan', '--format', 'json'], stderr=subprocess.DEVNULL)
        data = json.loads(result)
        cves = []
        for vuln in data.get('vulnerabilities', []):
            cve_id = vuln.get('id')
            desc   = vuln.get('title')
            sev    = vuln.get('severity')
            cves.append({'cve': cve_id, 'description': desc, 'severity': sev})
        return cves
    except Exception as e:
        console.print(f"[red]Error running debsecan: {e}[/red]")
        return []

def scan_remote(target, ports=None):
    """
    Perform Nmap version scan on the remote target.
    """
    if nmap is None:
        console.print("[red]python-nmap is not installed. Install with 'pip install python-nmap'.[/red]")
        return []
    nm = nmap.PortScanner()
    args = '-sV -Pn'
    if ports:
        args += f" -p {ports}"
    else:
        args += " -p-"
    console.print(f"[bold green]Running Nmap scan on {target}...[/bold green]")
    nm.scan(target, arguments=args)
    services = []
    if target in nm.all_hosts():
        for proto in nm[target].all_protocols():
            for port, svc in nm[target][proto].items():
                name    = svc.get('name', '')
                product = svc.get('product', '')
                version = svc.get('version', '')
                extrainfo = svc.get('extrainfo', '')
                if product or version:
                    info = f"{name} {product} {version} {extrainfo}".strip()
                    services.append(info)
    return services

def query_nvd(cpe_name=None, cve_id=None):
    """
    Query the NVD API for CVEs by CPE name or CVE ID.
    (Requires NVD API key for higher rate limits.)
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {}
    if cve_id:
        params['cveId'] = cve_id
    elif cpe_name:
        params['cpeName'] = cpe_name
    else:
        return {}
    headers = {}
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY
    try:
        res = requests.get(url, params=params, headers=headers)
        res.raise_for_status()
        return res.json()
    except Exception as e:
        console.print(f"[red]NVD API query error: {e}[/red]")
        return {}

def query_vulners(query):
    """
    Query the Vulners API for vulnerabilities.
    """
    if vulners is None:
        console.print("[red]Vulners library not installed. Install with 'pip install vulners'.[/red]")
        return []
    vulners_api = vulners.Vulners(api_key=VULNERS_API_KEY)
    try:
        results = vulners_api.search(query)
        return results
    except Exception as e:
        console.print(f"[red]Vulners API error: {e}[/red]")
        return []

def query_shodan(target):
    """
    Query Shodan for the target host.
    """
    if not SHODAN_API_KEY:
        console.print("[yellow]No Shodan API key set; skipping Shodan lookup.[/yellow]")
        return {}
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        hostinfo = api.host(target)
        return hostinfo
    except Exception as e:
        console.print(f"[red]Shodan query error: {e}[/red]")
        return {}

def query_securitytrails(domain=None, ip=None):
    """
    Query SecurityTrails for domain/IP information.
    """
    if not SECURITYTRAILS_API_KEY:
        console.print("[yellow]No SecurityTrails API key set; skipping SecurityTrails lookup.[/yellow]")
        return {}
    try:
        st_api = SecurityTrails(api_key=SECURITYTRAILS_API_KEY)
        if domain:
            return st_api.get_domain(domain)
        elif ip:
            return st_api.ip_explorer(ip)
    except Exception as e:
        console.print(f"[red]SecurityTrails query error: {e}[/red]")
    return {}

def search_exploits_by_cve(cve_list):
    """
    Use searchsploit to find exploits for each CVE.
    """
    exploits = defaultdict(list)
    for cve in cve_list:
        # Update local searchsploit DB if needed (silent)
        try:
            subprocess.check_output(['searchsploit', '-u'], stderr=subprocess.DEVNULL)
        except:
            pass
        try:
            res = subprocess.check_output(['searchsploit', '--cve', cve, '--json'])
            data = json.loads(res)
            for item in data.get('RESULTS_EXPLOIT', []):
                title = item.get('Title', '')
                path  = item.get('Path', '')
                exploits[cve].append({'title': title, 'path': path})
        except Exception as e:
            console.print(f"[red]searchsploit error for {cve}: {e}[/red]")
    return exploits

def generate_output(vulns, output_format='json', outfile=None):
    """
    Generate a report in JSON, HTML, or PDF format.
    """
    report = {
        'scan_date': datetime.now().isoformat(),
        'vulnerabilities': vulns
    }
    if output_format == 'json':
        text = json.dumps(report, indent=2)
        if outfile:
            with open(outfile, 'w') as f: f.write(text)
            console.print(f"[green]JSON report saved to {outfile}[/green]")
        else:
            print(text)
    elif output_format == 'html':
        # Simple HTML report (could use template)
        html = "<html><head><title>Vulnerability Report</title></head><body>"
        html += f"<h1>Vulnerability Report</h1><p>Scan date: {report['scan_date']}</p>"
        html += "<table border='1' cellpadding='5'><tr><th>CVE</th><th>Description</th><th>Severity</th></tr>"
        for v in vulns:
            html += ("<tr>"
                     f"<td>{v.get('cve','-')}</td>"
                     f"<td>{v.get('description','-')}</td>"
                     f"<td>{v.get('severity','-')}</td>"
                     "</tr>")
        html += "</table></body></html>"
        if outfile:
            with open(outfile, 'w') as f: f.write(html)
            console.print(f"[green]HTML report saved to {outfile}[/green]")
        else:
            print(html)
    elif output_format == 'pdf':
        # Generate HTML then convert via wkhtmltopdf
        html_file = outfile + ".html"
        generate_output(vulns, 'html', html_file)
        try:
            subprocess.run(['wkhtmltopdf', html_file, outfile], check=True)
            console.print(f"[green]PDF report saved to {outfile}[/green]")
        except Exception as e:
            console.print(f"[red]PDF generation failed: {e}[/red]")
    else:
        console.print(f"[red]Unknown format: {output_format}[/red]")

def interactive_cli():
    """
    Simple interactive prompt if no args given.
    """
    console.print("Select scan type:")
    console.print("1) Remote host (IP or domain)")
    console.print("2) Local system")
    choice = input("Enter choice [1-2]: ").strip()
    if choice == '1':
        target = input("Enter IP address or domain: ").strip()
    elif choice == '2':
        target = 'local'
    else:
        console.print("[red]Invalid choice[/red]")
        sys.exit(1)
    return target

def main():
    parser = argparse.ArgumentParser(description="CVEScannerX: Advanced CVE scanner")
    parser.add_argument('-t','--target', nargs=1,
        help="IP, domain, or 'local' for local system scan")
    parser.add_argument('-p','--ports', help="Comma-separated ports for Nmap (e.g. 80,443)")
    parser.add_argument('-f','--format', choices=['json','html','pdf'], default='json',
        help="Output format (json/html/pdf)")
    parser.add_argument('-o','--output', help="Output filename (without extension)")
    args = parser.parse_args()

    if args.target:
        target = args.target[0]
    else:
        target = interactive_cli()

    vulns_found = []  # list of {cve, description, severity}

    # Perform scan
    if target.lower() == 'local':
        # Local package vulnerability scan
        vulns_found = scan_local()
    else:
        # Resolve domain to IP if needed
        try:
            ip_addr = socket.gethostbyname(target)
        except Exception:
            ip_addr = target
        # Remote Nmap service scan
        services = scan_remote(target, args.ports)
        if services:
            console.print("[blue]Discovered services:[/blue]")
            for svc in services:
                console.print(f"  - {svc}")
        # Query Shodan (if IP)
        shodan_info = query_shodan(ip_addr)
        if shodan_info:
            console.print(f"[blue]Shodan data for {target}:[/blue]")
            console.print(json.dumps(shodan_info.get('data', {}), indent=2))
        # Query SecurityTrails (domain or IP)
        if '.' in target and not target.isdigit():
            sec_data = query_securitytrails(domain=target)
        else:
            sec_data = query_securitytrails(ip=ip_addr)
        if sec_data:
            console.print("[blue]SecurityTrails data:[/blue]")
            console.print(json.dumps(sec_data, indent=2))

        # For each service, query Vulners/NVD
        for svc in services:
            parts = svc.split()
            if len(parts) < 2: 
                continue
            product = parts[1]
            version = parts[2] if len(parts) > 2 else ''
            query = f"{product} {version}"
            console.print(f"[green]Searching vulnerabilities for: {query}[/green]")
            result = query_vulners(query)
            for entry in result.get('data', {}).get('search', []):
                cve_id = entry.get('id')
                title  = entry.get('title')
                cvss   = entry.get('cvss', '')
                vulns_found.append({'cve': cve_id, 'description': title, 'severity': cvss})

    # Deduplicate CVEs
    unique = {v['cve']: v for v in vulns_found if v.get('cve')}
    vulns_list = list(unique.values())

    # Correlate exploits via searchsploit
    cve_ids = [v['cve'] for v in vulns_list]
    exploits = search_exploits_by_cve(cve_ids)
    for v in vulns_list:
        v['exploits'] = exploits.get(v['cve'], [])

    # Display results in table
    table = Table(title="Detected Vulnerabilities")
    table.add_column("CVE", style="cyan")
    table.add_column("Description", style="magenta")
    table.add_column("Severity", justify="center")
    table.add_column("Exploits", justify="center")
    for v in vulns_list:
        exploit_titles = "\n".join([e['title'] for e in v['exploits']]) or "-"
        table.add_row(v.get('cve','-'), v.get('description','-'),
                      str(v.get('severity','-')), exploit_titles)
    console.print(table)

    # Write output file if requested
    if args.output:
        base = args.output
        fmt  = args.format
        outname = f"{base}.{fmt}"
        generate_output(vulns_list, fmt, outname)
    else:
        # Print JSON to stdout by default
        generate_output(vulns_list, args.format)

if __name__ == "__main__":
    main()
```

**Summary:** CVEScannerX provides a thorough, automated way to detect known CVEs on a target, using unauthenticated scans and multiple intelligence sources. It combines local package checks with Nmap-based service identification, queries official CVE databases (NVD), aggregators (Vulners), and exploit archives (Exploit-DB via searchsploit). The script’s modular design and clear output make it easy to integrate into Kali-based security assessments.





## more information
Perfect — here's how to turn your `CVEScannerX` into a polished, GitHub-ready project under your name **Muzan Sano**, with everything from proper structure, attribution, documentation, and push instructions.

---

## ✅ Project Structure (Best Practices)

```
CVEScannerX/
├── cvescannerx.py                # [✓] Main scanner script
├── README.md                     # [✓] Full documentation
├── LICENSE                       # [✓] Open-source license (MIT recommended)
├── requirements.txt              # [✓] Python dependencies
├── .gitignore                    # [✓] Ignore files like __pycache__/
└── docs/
    └── sample-report.html       # Example output
```

---

## ✅ 1. Add Author in Script(s)

At the top of `cvescannerx.py`:

```python
#!/usr/bin/env python3
# File: cvescannerx.py
# Author: Muzan Sano
# License: MIT
# Description: Advanced CVE scanner with multi-source intelligence for Kali Linux.
```

Apply `Author: Muzan Sano` in **every script, doc, or module** you create. Example for new modules:

```bash
# newmodule.py
# Author: Muzan Sano
# Purpose: [describe purpose]
```

---

## ✅ 2. Create `README.md`

Here's a full `README.md` template:

````markdown
# CVEScannerX

> Advanced CVE and exploit detection scanner for Kali Linux  
> **Author**: Muzan Sano

CVEScannerX is a powerful vulnerability assessment tool that detects known CVEs and correlates them with public exploits using multiple open intelligence sources. Built for cybersecurity researchers, red teamers, and bug bounty hunters.

---

## 🚀 Features

- 🔍 Local (Debian) and Remote (IP/Domain) scanning
- 🧠 CVE intelligence from: NVD, Vulners, ExploitDB, Shodan, SecurityTrails
- 🧨 Automatic exploit discovery (searchsploit)
- 📊 Output: JSON, HTML, optional PDF
- 🧪 Clean CLI with Rich TUI support
- ✅ Works seamlessly on Kali Linux

---

## 🛠 Installation

```bash
git clone https://github.com/yourusername/CVEScannerX.git
cd CVEScannerX
sudo apt update && sudo apt install nmap exploitdb debsecan wkhtmltopdf
pip3 install -r requirements.txt
````

Set your API keys:

```bash
export SHODAN_API_KEY="your-key"
export VULNERS_API_KEY="your-key"
export SECURITYTRAILS_API_KEY="your-key"
```

---

## 🔧 Usage

```bash
sudo python3 cvescannerx.py --target 192.168.1.100 --format html --output report
```

For local scan:

```bash
sudo python3 cvescannerx.py --target local --format json
```

---

## 📎 Sample Output

See `docs/sample-report.html` for an example scan report.

---

## 📜 License

MIT License — free to use, modify, and distribute with attribution.
**Author**: Muzan Sano

---

## 🤝 Contributing

Contributions and pull requests are welcome. Please open an issue first to discuss major changes.

````

---

## ✅ 3. Create `requirements.txt`

```txt
python-nmap
shodan
vulners
securitytrails
rich
requests
jinja2
````

---

## ✅ 4. Push to GitHub

### A. Create a new repo

* Go to [https://github.com/new](https://github.com/new)
* Repo name: `CVEScannerX`
* Add `.gitignore` for Python
* Add MIT License (recommended)

### B. Push from your Kali machine:

```bash
# Replace this with your actual GitHub repo URL
git clone https://github.com/yourusername/CVEScannerX.git
cd CVEScannerX

# Copy your project files into the repo directory
cp /path/to/cvescannerx.py .
cp /path/to/README.md .
cp /path/to/requirements.txt .

# Initialize git and push
git add .
git commit -m "Initial commit: CVEScannerX by Muzan Sano"
git push origin main
```

---

## ✅ 5. Bonus: Add GitHub Topics & Tags

In the GitHub UI:

* Add topics: `cve`, `scanner`, `kali-linux`, `offensive-security`, `python3`, `muzansano`, `bugbounty`
* Add description: “Advanced CVE scanner for Linux with multi-source vulnerability correlation and exploit mapping.”

---

Would you like me to generate:

* A custom logo/banner for your repo?
* A sample HTML/PDF report for the `docs/` folder?
* A `setup.py` or `Makefile` to install this as a package?

Let me know and I’ll include those too.
