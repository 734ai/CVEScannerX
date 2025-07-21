"""Remote system scanner module for CVEScannerX."""

import nmap
import time
import datetime
from typing import Dict, List, Optional
from ..utils.logger import get_logger
from ..utils.progress import ScanProgress
from ..utils.parallel import run_parallel

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

    def scan_single_target(self, target: str, ports: Optional[str] = None) -> Dict:
        """Scan a single target."""
        retries = self.config.get('max_retries', 3)
        current_try = 0
        
        while current_try < retries:
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
                    return {
                        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'target': target,
                            'error': 'No hosts found',
                            'status': 'failed'
                        }

                    progress.update(description="Processing scan results...")
                    result = {
                        'timestamp': scan_result['nmap']['scanstats']['timestr'],
                        'target': target,
                        'stats': scan_result['nmap']['scanstats'],
                        'status': 'success',
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
                    
                result = {
                    'timestamp': scan_result['nmap']['scanstats']['timestr'],
                    'target': target,
                    'stats': scan_result['nmap']['scanstats'],
                    'status': 'success',
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
                return result

            except nmap.PortScannerError as e:
                logger.error(f"Nmap scan error (attempt {current_try + 1}/{retries}): {e}")
                if current_try + 1 < retries:
                    time.sleep(2 ** current_try)  # Exponential backoff
                else:
                    raise
            except Exception as e:
                logger.error(f"Unexpected error during scan (attempt {current_try + 1}/{retries}): {e}")
                if current_try + 1 < retries:
                    time.sleep(2 ** current_try)  # Exponential backoff
                else:
                    raise
            
            current_try += 1
            
    def scan(self, targets: str | List[str], ports: Optional[str] = None) -> Dict:
        """Perform remote scan on one or multiple targets."""
        with ScanProgress("Remote scanning in progress") as progress:
            # Convert single target to list
            if isinstance(targets, str):
                targets = [targets]
            
            progress.update(description=f"Scanning {len(targets)} target(s)...")
            
            # Use parallel processing for multiple targets
            max_workers = self.config.get('max_parallel_scans', 5)
            results = run_parallel(
                self.scan_single_target,
                targets,
                max_workers=max_workers,
                ports=ports
            )
            
            # Combine results
            combined_results = {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'targets': targets,
                'total_scanned': len(results),
                'successful_scans': len([r for r in results if r['status'] == 'success']),
                'results': results
            }
            
            progress.update(description="Remote scanning complete!")
            return combined_results
