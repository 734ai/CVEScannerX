# CVEScannerX

Advanced CVE scanning tool for Kali Linux that combines local package checks and remote Nmap-based service detection with multiple vulnerability intelligence APIs. Features parallel processing capabilities and comprehensive reporting.

## Features

* **Local and Remote Scanning:** 
  * Local system scanning with debsecan
  * Remote scanning with Nmap version detection
  * Parallel scanning for multiple targets
  * Service and port analysis

* **Multi-Source CVE Intelligence:** 
  * NVD API integration with caching
  * Vulners API for vulnerability data
  * Exploit-DB correlation via searchsploit
  * Shodan integration for additional context
  * SecurityTrails for domain reconnaissance

* **Performance & Reliability:**
  * Parallel processing for faster scans
  * Efficient API call optimization
  * Robust error handling
  * Rate limiting and caching

* **Rich Reporting:**
  * Modern HTML reports with CSS styling
  * PDF export via wkhtmltopdf
  * Structured JSON output
  * Comprehensive metadata
  * Exploit correlation data

* **Security & Stability:**
  * Security audited
  * Production-ready
  * Extensive test coverage
  * API key protection

## Installation

1. System Dependencies:
```bash
sudo apt update
sudo apt install -y nmap exploitdb debsecan wkhtmltopdf
```

2. Install CVEScannerX:
```bash
pip install cvescannerx
```

3. API Keys:
Set up the following environment variables with your API keys:
```bash
export SHODAN_API_KEY="YOUR_SHODAN_KEY"
export VULNERS_API_KEY="YOUR_VULNERS_KEY"
export SECURITYTRAILS_API_KEY="YOUR_SECURITYTRAILS_KEY"
export NVD_API_KEY="YOUR_NVD_KEY"
```

## Configuration

The tool can be configured through environment variables or a configuration file. Create `~/.config/cvescannerx/config.json`:

```json
{
    "features": {
        "scanning": {
            "local": {
                "enabled": true,
                "requires_sudo": true,
                "scan_types": ["packages", "services", "ports"]
            },
            "remote": {
                "enabled": true,
                "default_ports": "1-1000",
                "timeout": 300,
                "max_parallel_scans": 5,
                "options": {
                    "service_detection": true,
                    "os_detection": true,
                    "script_scan": false
                }
            }
        }
    }
}

## Usage

### Command Line Interface

```bash
# Interactive Mode
cvescannerx

# Local System Scan
sudo cvescannerx --target local --format html --output local_scan

# Remote Target Scan
cvescannerx --target 192.168.1.100 --format pdf --output remote_scan

# Multiple Target Scan
cvescannerx --target "192.168.1.100,192.168.1.101" --ports "80,443,8080" --format json
```

### Command Line Options

- `--target`: Target specification
  - Single IP or domain
  - Multiple targets (comma-separated)
  - "local" for local system scan
- `--ports`: Ports to scan (remote only)
  - Comma-separated list
  - Range notation (e.g., "80-443")
  - Default: top 1000 ports
- `--format`: Output format
  - json: Machine-readable output
  - html: Interactive web report
  - pdf: Printable documentation
- `--output`: Base name for output files

### Python API

```python
from cvescannerx import CVEScannerX

# Initialize scanner
scanner = CVEScannerX()

# Local system scan
results = scanner.scan_local()

# Remote scan
remote_results = scanner.scan_remote(
    target="192.168.1.100",
    ports="80,443"
)

# Generate report
scanner.generate_report(results, format="html", output="scan_report")

## License

MIT License

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
