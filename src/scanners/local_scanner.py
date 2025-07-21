"""Local system scanner module for CVEScannerX."""

import json
import subprocess
from typing import Dict, List, Optional, Tuple, Callable
from ..utils.logger import get_logger
from ..utils.parallel import run_parallel
from ..utils.progress import ScanProgress

logger = get_logger(__name__)

class LocalScanner:
    """Scanner for local system packages and services."""
    
    def __init__(self, config: Dict):
        """Initialize local scanner with configuration."""
        self.config = config
        self.scan_types = config['features']['scanning']['local']['scan_types']

    def scan_packages(self) -> Dict:
        """Scan local packages using debsecan."""
        try:
            result = subprocess.run(
                ['debsecan', '--format=json'],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to run debsecan: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse debsecan output: {e}")
            raise

    def scan_services(self) -> Dict:
        """Scan local running services."""
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--output=json'],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to scan services: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse services output: {e}")
            raise

    def scan_ports(self) -> Dict:
        """Scan local listening ports."""
        try:
            result = subprocess.run(
                ['ss', '-tuln', '--json'],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to scan ports: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse ports output: {e}")
            raise

    def _get_scan_function(self, scan_type: str) -> Tuple[Callable, str]:
        """Get the scan function and description for a scan type."""
        scan_functions = {
            'packages': (self.scan_packages, "Scanning installed packages"),
            'services': (self.scan_services, "Scanning running services"),
            'ports': (self.scan_ports, "Scanning open ports")
        }
        return scan_functions.get(scan_type, (None, ""))

    def scan(self) -> Dict:
        """Perform a complete local system scan."""
        results = {
            'timestamp': subprocess.check_output(['date', '+%s']).decode().strip(),
            'hostname': subprocess.check_output(['hostname']).decode().strip(),
            'scans': {}
        }

        with ScanProgress("Scanning local system") as progress:
            # Filter enabled scan types
            enabled_scans = [(t, *self._get_scan_function(t)) 
                           for t in self.scan_types 
                           if t in ['packages', 'services', 'ports']]
            
            progress.update(description=f"Starting {len(enabled_scans)} scan types...")
            
            # Run scans in parallel
            scan_results = run_parallel(
                lambda x: (x[0], x[1]()), 
                enabled_scans,
                max_workers=len(enabled_scans)
            )
            
            # Process results
            for scan_type, result in scan_results:
                results['scans'][scan_type] = result
            
            progress.update(description="Scan complete!")

        return results
