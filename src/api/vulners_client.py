"""Vulners API client for CVEScannerX."""

import time
import vulners
from typing import Dict, List, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)

class VulnersClient:
    """Client for the Vulners vulnerability database API."""
    
    def __init__(self, config: Dict):
        """Initialize Vulners API client."""
        self.config = config['api_config']['vulners']
        self.api = None
        self.last_request_time = 0
        self.min_request_interval = 60.0 / self.config['rate_limit']['requests_per_minute']

    def set_api_key(self, api_key: str) -> None:
        """Set up the Vulners API client with an API key."""
        try:
            self.api = vulners.Vulners(api_key=api_key)
        except Exception as e:
            logger.error(f"Failed to initialize Vulners API client: {e}")
            raise

    def _rate_limit(self) -> None:
        """Implement rate limiting for API requests."""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()

    def search_vulnerabilities(self, 
                             query: str,
                             limit: int = 100) -> List[Dict]:
        """Search for vulnerabilities using a text query."""
        if not self.api:
            raise RuntimeError("Vulners API client not initialized. Call set_api_key first.")
            
        self._rate_limit()
        try:
            return self.api.search(query, limit=limit)
        except Exception as e:
            logger.error(f"Error searching vulnerabilities: {e}")
            raise

    def get_cve_details(self, cve_id: str) -> Dict:
        """Get detailed information about a specific CVE."""
        if not self.api:
            raise RuntimeError("Vulners API client not initialized. Call set_api_key first.")
            
        self._rate_limit()
        try:
            return self.api.document(cve_id)
        except Exception as e:
            logger.error(f"Error fetching CVE details: {e}")
            raise

    def scan_software(self, name: str, version: str) -> List[Dict]:
        """Search for vulnerabilities in specific software version."""
        if not self.api:
            raise RuntimeError("Vulners API client not initialized. Call set_api_key first.")
            
        self._rate_limit()
        try:
            return self.api.software(name, version)
        except Exception as e:
            logger.error(f"Error scanning software: {e}")
            raise
