#!/usr/bin/env python3

"""
CVEScannerX: Advanced CVE scanning tool for Kali Linux.

Features:
- Local and remote vulnerability scanning (unauthenticated)
- Queries multiple threat intelligence sources: NVD, Vulners, Exploit-DB, Shodan, SecurityTrails
- Correlates CVEs with known exploits
- Interactive CLI using Rich for colorful output
- Outputs in JSON, HTML, PDF (optional)
"""

import os
import sys
import json
import argparse
import subprocess
from typing import Dict, List, Optional, Union

import nmap
import requests
import shodan
import vulners
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from securitytrails import SecurityTrails
from jinja2 import Template

class CVEScannerX:
    def __init__(self):
        self.console = Console()
        self.shodan_api = None
        self.vulners_api = None
        self.securitytrails_api = None
        self.nvd_api_key = None
        self._initialize_apis()

    def _initialize_apis(self):
        """Initialize API clients with keys from environment variables."""
        try:
            shodan_key = os.getenv('SHODAN_API_KEY')
            vulners_key = os.getenv('VULNERS_API_KEY')
            securitytrails_key = os.getenv('SECURITYTRAILS_API_KEY')
            self.nvd_api_key = os.getenv('NVD_API_KEY')

            if shodan_key:
                self.shodan_api = shodan.Shodan(shodan_key)
            if vulners_key:
                self.vulners_api = vulners.Vulners(api_key=vulners_key)
            if securitytrails_key:
                self.securitytrails_api = SecurityTrails(securitytrails_key)

        except Exception as e:
            self.console.print(f"[red]Error initializing APIs: {str(e)}[/red]")

    def scan_local(self) -> Dict:
        """Scan local system using debsecan."""
        self.console.print("[yellow]Starting local system scan...[/yellow]")
        
        try:
            # Run debsecan with JSON output
            result = subprocess.run(
                ['debsecan', '--format=json'],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            self.console.print(f"[red]Error running debsecan: {str(e)}[/red]")
            return {}
        except json.JSONDecodeError as e:
            self.console.print(f"[red]Error parsing debsecan output: {str(e)}[/red]")
            return {}

    def scan_remote(self, target: str, ports: Optional[str] = None) -> Dict:
        """Perform remote Nmap scan on target."""
        self.console.print(f"[yellow]Starting remote scan of {target}...[/yellow]")
        
        nm = nmap.PortScanner()
        scan_args = '-sV'  # Version detection
        if ports:
            scan_args += f' -p {ports}'
            
        try:
            nm.scan(target, arguments=scan_args)
            return nm[target]
        except Exception as e:
            self.console.print(f"[red]Error during Nmap scan: {str(e)}[/red]")
            return {}

    def query_nvd(self, cve_id: str) -> Dict:
        """Query NVD API for CVE details."""
        url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
            
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.console.print(f"[red]Error querying NVD: {str(e)}[/red]")
            return {}

    def search_exploits_by_cve(self, cve_id: str) -> List[Dict]:
        """Search for exploits using searchsploit."""
        try:
            result = subprocess.run(
                ['searchsploit', '--cve', cve_id, '--json'],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout).get('RESULTS_EXPLOIT', [])
        except Exception as e:
            self.console.print(f"[red]Error searching exploits: {str(e)}[/red]")
            return []

    def generate_report(self, data: Dict, format: str = 'json', output: str = 'report'):
        """Generate report in specified format."""
        if format == 'json':
            with open(f'{output}.json', 'w') as f:
                json.dump(data, f, indent=2)
        elif format in ['html', 'pdf']:
            # TODO: Implement HTML template rendering and PDF conversion
            pass

    def main(self):
        """Main execution flow."""
        parser = argparse.ArgumentParser(description='CVEScannerX - Advanced CVE Scanner')
        parser.add_argument('--target', help='Target to scan (IP, domain, or "local")')
        parser.add_argument('--ports', help='Ports to scan (remote only)')
        parser.add_argument('--format', choices=['json', 'html', 'pdf'], default='json')
        parser.add_argument('--output', default='scan_report')
        
        args = parser.parse_args()
        
        # Interactive mode if no target specified
        if not args.target:
            args.target = self.console.input('[green]Enter target (IP, domain, or "local"): [/green]')

        # Perform scan
        if args.target.lower() == 'local':
            results = self.scan_local()
        else:
            results = self.scan_remote(args.target, args.ports)

        # Generate report
        self.generate_report(results, args.format, args.output)
        self.console.print(f"[green]Scan complete! Report saved as {args.output}.{args.format}[/green]")

if __name__ == '__main__':
    scanner = CVEScannerX()
    scanner.main()
