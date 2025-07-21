"""Local system scanner module for CVEScannerX."""

import json
import subprocess
from typing import Dict, List, Optional
from ..utils.logger import get_logger

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

    def scan(self) -> Dict:
        """Perform a complete local system scan."""
        results = {
            'timestamp': subprocess.check_output(['date', '+%s']).decode().strip(),
            'hostname': subprocess.check_output(['hostname']).decode().strip(),
            'scans': {}
        }

        if 'packages' in self.scan_types:
            results['scans']['packages'] = self.scan_packages()
        if 'services' in self.scan_types:
            results['scans']['services'] = self.scan_services()
        if 'ports' in self.scan_types:
            results['scans']['ports'] = self.scan_ports()

        return results
