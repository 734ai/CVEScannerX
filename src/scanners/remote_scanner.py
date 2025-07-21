"""Remote system scanner module for CVEScannerX."""

import nmap
from typing import Dict, List, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)

class RemoteScanner:
    """Scanner for remote systems using Nmap."""
    
    def __init__(self, config: Dict):
        """Initialize remote scanner with configuration."""
        self.config = config['features']['scanning']['remote']
        self.nm = nmap.PortScanner()

    def build_scan_arguments(self, target: str, ports: Optional[str] = None) -> str:
        """Build Nmap scan arguments based on configuration."""
        args = ['-sV']  # Service version detection
        
        if self.config['options']['os_detection']:
            args.append('-O')
        
        if self.config['options']['script_scan']:
            args.append('-sC')  # Default script scan
        
        if ports:
            args.append(f'-p {ports}')
        else:
            args.append(f'-p {self.config["default_ports"]}')
            
        return ' '.join(args)

    def scan(self, target: str, ports: Optional[str] = None) -> Dict:
        """Perform remote scan on target."""
        try:
            args = self.build_scan_arguments(target, ports)
            logger.info(f"Starting scan of {target} with arguments: {args}")
            
            scan_result = self.nm.scan(
                target,
                arguments=args,
                timeout=self.config['timeout']
            )

            if target not in self.nm.all_hosts():
                logger.warning(f"No results found for target: {target}")
                return {}

            return {
                'timestamp': scan_result['nmap']['scanstats']['timestr'],
                'target': target,
                'stats': scan_result['nmap']['scanstats'],
                'hosts': {
                    target: {
                        'status': self.nm[target].state(),
                        'os': self.nm[target].get('osmatch', []),
                        'ports': self.nm[target].get('tcp', {}),
                        'hostnames': self.nm[target].hostnames(),
                        'vendor': self.nm[target].get('vendor', {})
                    }
                }
            }

        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            raise
