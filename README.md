# CVEScannerX

Advanced CVE scanning tool for Kali Linux that combines local package checks and remote Nmap-based service detection with multiple vulnerability intelligence APIs.

## Features

* **Local and Remote Scanning:** Supports local (Debian package) and remote (IP/domain) scans
* **Multi-Source CVE Intelligence:** Queries NVD API, Vulners, Exploit-DB (via searchsploit), Shodan, and SecurityTrails
* **CVE-Exploit Correlation:** Uses `searchsploit --cve` with JSON output to link CVEs to exploits
* **Interactive CLI/TUI:** Offers prompts and colored tables using Rich library
* **Structured Output:** Saves results in JSON, HTML (and PDF via wkhtmltopdf)
* **Modular & Configurable:** Written in Python 3, organized into functions; API keys configurable via environment

## Installation

1. System Dependencies:
```bash
sudo apt update
sudo apt install -y nmap exploitdb debsecan wkhtmltopdf
```

2. Python Dependencies:
```bash
pip3 install -r requirements.txt
```

3. API Keys:
Set up the following environment variables with your API keys:
```bash
export SHODAN_API_KEY="YOUR_SHODAN_KEY"
export VULNERS_API_KEY="YOUR_VULNERS_KEY"
export SECURITYTRAILS_API_KEY="YOUR_SECURITYTRAILS_KEY"
export NVD_API_KEY="YOUR_NVD_KEY"  # optional
```

## Usage

Make the script executable:
```bash
chmod +x src/cvescannerx.py
```

### Examples:

1. Interactive Mode:
```bash
sudo ./src/cvescannerx.py
```

2. Remote Scan:
```bash
sudo ./src/cvescannerx.py --target 192.168.1.100 --format html --output scan_report
```

3. Local System Scan:
```bash
sudo ./src/cvescannerx.py --target local --format json --output local_scan
```

### Command Line Options:

- `--target`: IP address, domain name, or "local" for local system scan
- `--ports`: Specific ports to scan (remote only, comma-separated)
- `--format`: Output format (json, html, or pdf)
- `--output`: Base name for output files

## License

MIT License

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
